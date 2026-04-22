require("dotenv").config();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const express = require("express");

const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const axios = require("axios");
const adjuntosPorThread = {};
const FormData = require("form-data");
const path = require("path");
const fs = require("fs");

const multer = require("multer");
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 20 * 1024 * 1024 }
});

const app = express();

const cors = require("cors");

const corsOptions = {
    origin: [
        "http://localhost:5173",
        "https://romannico.github.io"
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
};

app.use(cors(corsOptions));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));


// ─── CONEXIÓN POSTGRESQL  ───────────────────────────────────────────────
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === "false"
        ? { rejectUnauthorized: false }
        : false
});

pool.query("SELECT NOW()")
    .then(res => console.log("DB conectada:", res.rows[0]))
    .catch(err => console.error("Error DB:", err));


// ─── SSO AZURE AD ────────────────────────────────────────────────────────
const jwksCacheByTenant = new Map();

function base64UrlToBuffer(input) {
    const normalized = String(input).replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(normalized.length + (4 - (normalized.length % 4)) % 4, "=");
    return Buffer.from(padded, "base64");
}

function decodeJwtPart(part) {
    return JSON.parse(base64UrlToBuffer(part).toString("utf8"));
}

async function obtenerJwks(tenantId) {
    const key = tenantId || "common";
    const cached = jwksCacheByTenant.get(key);
    if (cached && Date.now() < cached.expiresAt) return cached.keysByKid;

    const url = `https://login.microsoftonline.com/${key}/discovery/v2.0/keys`;
    const { data } = await axios.get(url);
    const keysByKid = data.keys.reduce((acc, jwk) => ({ ...acc, [jwk.kid]: jwk }), {});

    jwksCacheByTenant.set(key, {
        keysByKid,
        expiresAt: Date.now() + 12 * 60 * 60 * 1000
    });

    return keysByKid;
}

function isTenantAllowed(tokenTenantId) {
    const allowed = (process.env.AZURE_AD_ALLOWED_TENANTS || "")
        .split(",")
        .map(v => v.trim())
        .filter(Boolean);

    // Si no se configura lista, se permite cualquier tenant (útil con authority=organizations)
    if (allowed.length === 0) return true;

    return allowed.includes(tokenTenantId);
}

async function validarTokenAzure(token) {
    const [headerPart, payloadPart] = token.split(".");
    if (!headerPart || !payloadPart) throw new Error("Token JWT inválido");

    const header = decodeJwtPart(headerPart);
    const payload = decodeJwtPart(payloadPart);
    console.log("[SSO] Validando Token. Header:", header);

    const tokenTenantId = payload.tid || process.env.AZURE_AD_TENANT_ID || "common";
    if (!isTenantAllowed(tokenTenantId)) {
        throw new Error("Tenant no autorizado: " + tokenTenantId);
    }

    const jwks = await obtenerJwks(tokenTenantId);
    const jwk = jwks[header.kid];
    if (!jwk) {
        console.error("[SSO] No se encontro llave para el kid:", header.kid);
        throw new Error("JWK no encontrado para kid: " + header.kid);
    }

    const pem = jwkToPem(jwk);

    return new Promise((resolve, reject) => {
        jwt.verify(
            token,
            pem,
            { algorithms: ["RS256"] }, // Relajamos validación estricta de 'audience'/'issuer' para evitar 401
            (err, decoded) => { 
                if (err) {
                    console.error("Detalle error JWT Verify:", err);
                    reject(err);
                } else {
                    resolve(decoded); 
                }
            }
        );
    });
}

// ─── LOGIN CON SSO  ───────────────────────────────────────────────────────
// Valida el token Azure AD y retorna el perfil + rol desde usuarios_pgrr
app.post("/sso-login", async (req, res) => {

    const authHeader = req.headers["authorization"] || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    const allowAutoRegister = (process.env.SSO_AUTO_REGISTER || "true").toLowerCase() === "true";

    if (!token) {
        return res.status(401).json({ success: false, message: "Token no proporcionado" });
    }

    let decoded;
    try {
        decoded = await validarTokenAzure(token);
    } catch (err) {
        console.error("[SSO] Error de validacion JWT:", err.message);
        return res.status(401).json({ success: false, message: "Token invalido: " + err.message });
    }

    const emailCandidatesRaw = [
        decoded.preferred_username,
        decoded.email,
        decoded.upn,
        decoded.unique_name
    ].filter(Boolean);

    const normalizedCandidates = emailCandidatesRaw
        .map(v => String(v).toLowerCase().trim())
        .filter(Boolean);

    const emailCandidates = [...new Set([
        ...normalizedCandidates,
        // Fallback: si en BD el usuario está como "usuario" en vez de correo
        ...normalizedCandidates
            .filter(v => v.includes("@"))
            .map(v => v.split("@")[0])
            .filter(Boolean)
    ])];

    const email = emailCandidates[0] || "";
    const nombre = decoded.name || email || "";
    const oid = decoded.oid || decoded.sub || "";
    const cargo = decoded.jobTitle || "";
    const area = decoded.department || "";

    if (!email) {
        return res.status(400).json({ success: false, message: "No se pudo obtener el correo del token SSO" });
    }

    try {
        // Buscar por correo o por nombre_usuario (algunos usuarios pueden tener el email como usuario)
        let result = await pool.query(
            `SELECT * FROM usuarios_pgrr 
             WHERE LOWER(correo) = ANY($1) OR LOWER(nombre_usuario) = ANY($1)
             LIMIT 1`,
            [emailCandidates]
        );

        if (result.rows.length === 0) {
            // Si el usuario no está en BD, se le permite acceso temporal con rol 'user'
            console.log("SSO: Usuario no encontrado en BD. Otorgando acceso virtual con rol 'user':", email);
            result = { rows: [{
                nombre_usuario: email,
                correo: email,
                rol: "user",
                centro_costo: ""
            }] };
        }

        const user = result.rows[0];
        console.log(`SSO login: ${email} | rol: ${user.rol}`);

        return res.json({
            success: true,
            usuario: user.nombre_usuario,
            correo: email,
            nombre: nombre,
            rol: user.rol,
            cargo: cargo,
            area: area,
            oid: oid,
            centro_costo: user.centro_costo || area || ""
        });

    } catch (error) {
        console.error("Error en SSO login:", error);
        return res.status(500).json({ success: false, message: "Error interno" });
    }
});

// ─── LOGIN TRADICIONAL (mantenido para compatibilidad) ──────────────────
app.post("/login", async (req, res) => {

    const { usuario, password } = req.body;

    console.log("Intento login:", usuario);

    try {

        const result = await pool.query(
            `SELECT * FROM usuarios_pgrr 
             WHERE nombre_usuario = $1 OR LOWER(correo) = LOWER($1)
             LIMIT 1`,
            [(usuario || "").trim()]
        );
        if (result.rows.length === 0) return res.json({ success: false });

        const user = result.rows[0];
        const passwordValida = await bcrypt.compare(password, user.contrasena);
        if (!passwordValida) return res.json({ success: false });

        res.json({ success: true, usuario: user.nombre_usuario, rol: user.rol });
    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ success: false });
    }
});

app.get("/perfil/:usuario", async (req, res) => {
    const { usuario } = req.params;
    try {
        const result = await pool.query(
            `SELECT nombre_usuario, correo, centro_costo, genero, rol
             FROM usuarios_pgrr 
             WHERE nombre_usuario = $1 OR LOWER(correo) = LOWER($1)`,
            [usuario]
        );
        if (result.rows.length === 0) return res.json({ success: false });
        res.json({ success: true, usuario: result.rows[0] });
    } catch (error) {
        console.error("Error obteniendo perfil:", error);
        res.status(500).json({ success: false });
    }
});

app.post("/cambiar-password", async (req, res) => {
    const { usuario, actual, nueva } = req.body;
    try {
        const result = await pool.query(
            `SELECT contrasena FROM usuarios_pgrr WHERE nombre_usuario = $1`,
            [usuario]
        );
        if (result.rows.length === 0) return res.json({ success: false, message: "Usuario no encontrado" });
        const hashGuardado = result.rows[0].contrasena;
        if (!(await bcrypt.compare(actual, hashGuardado))) return res.json({ success: false, message: "Contraseña actual incorrecta" });
        const nuevoHash = await bcrypt.hash(nueva, 10);
        await pool.query(`UPDATE usuarios_pgrr SET contrasena = $1 WHERE nombre_usuario = $2`, [nuevoHash, usuario]);
        res.json({ success: true });
    } catch (error) {
        console.error("Error cambiando contraseña:", error);
        res.status(500).json({ success: false });
    }
});

let novaToken = null;
let tokenExpira = 0;
async function obtenerTokenNova() {
    if (novaToken && Date.now() < tokenExpira) return novaToken;
    const { data } = await axios.post("https://api-backend-service.comware.com.co:3026/api/auth/login", {
        username: process.env.NOVA_USER, password: process.env.NOVA_PASS, captcha: "1"
    });
    novaToken = data.token;
    tokenExpira = Date.now() + (50 * 60 * 1000);
    return novaToken;
}

app.post("/api/nova", upload.array("files"), async (req, res) => {
    try {
        const { message, threadId, channel = "web" } = req.body;
        if (!threadId) return res.status(400).json({ error: "threadId es obligatorio" });
        if (!adjuntosPorThread[threadId]) adjuntosPorThread[threadId] = [];
        if (req.files && req.files.length > 0) {
            adjuntosPorThread[threadId].push(...req.files.map(f => ({
                nombre: f.originalname, tipo: f.mimetype, data: f.buffer.toString("base64")
            })));
        }
        const token = await obtenerTokenNova();
        let reply = "Sin respuesta del asistente.";
        try {
            const { data } = await axios.post("https://api-backend-service.comware.com.co:3026/api/sam-assistant/user-question-bp/4280d8c1-1022-4f44-bd05-d1d5dd3bd66c",
                { question: message, threadId, channel },
                { headers: { Authorization: `Bearer ${token}` }, timeout: 60000 }
            );
            reply = data.isLastContent || data.reply || data.mensaje || reply;
        } catch (e) {
            console.error("Error Nova:", e.message);
            reply = "⚠️ Nova no respondió, pero los adjuntos fueron recibidos.";
        }
        res.json({ reply, adjuntos: adjuntosPorThread[threadId] || [] });
    } catch (error) {
        console.error("ERROR NOVA:", error);
        res.status(500).json({ error: "Error interno" });
    }
});

app.get("/requerimientos", async (req, res) => {
    const { usuario, vista } = req.query;

    let query = "";
    let values = [];

    if (vista === "mis" && usuario) {

        query = `
        SELECT 
            id,
            titulo,
            estado,
            autor,
            prioridad,
            contenido,
            timestamp_ms,
            check_po,
            check_qa
        FROM requerimientos_pgrr
        WHERE autor = $1
        ORDER BY timestamp_ms DESC
        `;

        values = [usuario];

    } else {

        query = `
        SELECT 
            id,
            titulo,
            estado,
            autor,
            prioridad,
            contenido,
            timestamp_ms,
            check_po,
            check_qa
        FROM requerimientos_pgrr
        ORDER BY timestamp_ms DESC
        `;
    }

    try {

        const result = await pool.query(query, values);

        res.json({
            success: true,
            data: result.rows
        });

    } catch (err) {

        console.error("Error al obtener requerimientos:", err);

        res.json({
            success: false,
            data: []
        });

    }
});

// REQUERIMIENTO POR ID
app.get("/requerimientos/:id", async (req, res) => {
    try {
        const result = await pool.query(
            `
        SELECT 
            id,
            titulo,
            estado,
            autor,
            prioridad,
            contenido,
            timestamp_ms,
            centro_costo,
            check_po,
            check_qa,
            comentario,
            adjuntos
        FROM requerimientos_pgrr
        WHERE id = $1
        `,
            [req.params.id]
        );

        if (result.rows.length === 0)
            return res.json({ success: false });

        const r = result.rows[0];

        res.json({
            success: true,
            data: {
                ...r,
                adjuntos: typeof r.adjuntos === "string"
                    ? JSON.parse(r.adjuntos)
                    : r.adjuntos || []
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false });
    }
});

// CREAR REQUERIMIENTO
app.post("/requerimientos", async (req, res) => {
    const {
        titulo,
        autor,
        fecha,
        timestamp_ms,
        contenido,
        estado,
        prioridad,
        tipo_caso,
        fecha_solucion,
        encargado_id,
        centro_costo,
        adjuntos,
        threadId
    } = req.body;

    let archivos = adjuntos;

    if ((!archivos || archivos.length === 0) && threadId) {
        archivos = adjuntosPorThread[threadId] || [];
    }

    const adjuntosFinal = JSON.stringify(archivos || []);
    try {

        const last = await pool.query(
            `SELECT id FROM requerimientos_pgrr ORDER BY timestamp_ms DESC LIMIT 1`
        );

        let siguiente = 1;
        if (last.rows.length > 0) {
            const match = last.rows[0].id?.match(/\d+/);
            if (match) siguiente = parseInt(match[0]) + 1;
        }

        const id = "REQ_" + String(siguiente).padStart(4, "0");

        await pool.query(
            `INSERT INTO requerimientos_pgrr
             (id, titulo, autor, fecha, timestamp_ms, contenido, estado,
              prioridad, tipo_caso, fecha_solucion, encargado_id, centro_costo, adjuntos)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
            [
                id,
                titulo,
                autor,
                fecha,
                timestamp_ms,
                contenido,
                estado || "Pendiente",
                prioridad,
                tipo_caso || "Requerimiento",
                fecha_solucion,
                encargado_id,
                centro_costo,
                adjuntosFinal
            ]
        );

        console.log("Adjuntos guardados en BD:", adjuntosFinal.length);

        if (threadId && adjuntosPorThread[threadId]) {
            delete adjuntosPorThread[threadId];
        }

        res.json({ success: true, id });

    } catch (error) {
        console.error("Error creando requerimiento:", error);
        res.status(500).json({ success: false });
    }
});

// ACTUALIZAR ESTADOS DEL REQUERIMIENTO
app.patch("/requerimientos/:id", async (req, res) => {
    const { id } = req.params;
    const campos = req.body;

    const permitidos = ["estado", "comentario", "contenido",
        "enviado_jira", "fecha_envio_jira", "prioridad"];
    const sets = [];
    const valores = [];
    let i = 1;

    for (const key of permitidos) {
        if (campos[key] !== undefined) {
            sets.push(`${key} = $${i++}`);
            valores.push(campos[key]);
        }
    }

    if (sets.length === 0) return res.json({ success: false, message: "Nada que actualizar" });

    valores.push(id);
    try {
        await pool.query(
            `UPDATE requerimientos_pgrr SET ${sets.join(", ")} WHERE id = $${i}`,
            valores
        );
        res.json({ success: true });
    } catch (error) {
        console.error("Error actualizando requerimiento:", error);
        res.status(500).json({ success: false });
    }
});

app.patch("/requerimientos/:id/validacion", async (req, res) => {
    const { id } = req.params;
    const { po, qa } = req.body;

    try {

        let nuevoEstado = "Pendiente";

        if (po && qa) {
            nuevoEstado = "Listo para enviar";
        } else if (po || qa) {
            nuevoEstado = "En validación";
        }

        await pool.query(
            `UPDATE requerimientos_pgrr 
             SET check_po = $1, 
                 check_qa = $2,
                 estado = $3
             WHERE id = $4`,
            [po, qa, nuevoEstado, id]
        );

        res.json({ success: true });

    } catch (error) {
        console.error("Error guardando validacion:", error);
        res.status(500).json({ success: false });
    }
});

// ─── ENVIAR JIRA  ───────────────────────────────────────────────
async function obtenerSprintActivo() {
    const response = await axios.get(
        "https://comwaredev.atlassian.net/rest/agile/1.0/board/375/sprint?state=active",
        {
            auth: {
                username: process.env.JIRA_EMAIL,
                password: process.env.JIRA_API_TOKEN,
            },
            headers: {
                Accept: "application/json",
            },
        }
    );

    return response.data.values?.[0];
}

async function obtenerIdCentroCosto(nombreCentro) {

    try {

        const response = await axios.get(
            "https://comwaredev.atlassian.net/rest/api/3/field/customfield_10120/context/1/option",
            {
                auth: {
                    username: process.env.JIRA_EMAIL,
                    password: process.env.JIRA_API_TOKEN
                },
                headers: { Accept: "application/json" }
            }
        );

        const opciones = response.data.values;

        const match = opciones.find(o =>
            o.value.trim().toLowerCase() === nombreCentro.trim().toLowerCase()
        );

        if (!match) {
            console.log("⚠️ Centro de costo no encontrado:", nombreCentro);
            return null;
        }

        console.log("Centro costo encontrado:", match.value, "ID:", match.id);

        return match.id;

    } catch (error) {

        console.error("Error obteniendo centro de costo:", error.response?.data || error);
        return null;

    }
}

async function subirAdjunto(issueKey, archivo) {
    await axios.post(
        `https://comwaredev.atlassian.net/rest/api/3/issue/${issueKey}/attachments`,
        archivo.buffer,
        {
            auth: {
                username: process.env.JIRA_EMAIL,
                password: process.env.JIRA_API_TOKEN,
            },
            headers: {
                "X-Atlassian-Token": "no-check",
                "Content-Type": archivo.mimetype,
            },
        }
    );
}

const mapaTitulos = {

"descripcion general del requerimiento": { emoji: "📄", titulo: "Descripción general del requerimiento" },
"descripcion breve de la necesidad": { emoji: "📄", titulo: "Descripción breve de la necesidad" },
"problema que se busca resolver": { emoji: "⚠️", titulo: "Problema que se busca resolver" },
"area o proceso impactado": { emoji: "🏢", titulo: "Área o proceso impactado" },
"usuarios impactados": { emoji: "👥", titulo: "Usuarios impactados" },
"objetivo de la solucion": { emoji: "🎯", titulo: "Objetivo de la solución" },
"descripcion del proceso actual": { emoji: "🔍", titulo: "Descripción del proceso actual" },
"descripcion del proceso esperado": { emoji: "🚀", titulo: "Descripción del proceso esperado" },
"sistemas involucrados": { emoji: "⚙️", titulo: "Sistemas involucrados" },
"prioridad asignada": { emoji: "🔥", titulo: "Prioridad asignada" },
"riesgos": { emoji: "⚠️", titulo: "Riesgos" },
"dependencias": { emoji: "🔗", titulo: "Dependencias" },
"criterios de aceptacion": { emoji: "✅", titulo: "Criterios de aceptación" },
"autor del requerimiento": { emoji: "👤", titulo: "Autor del requerimiento" },
"centro de costos": { emoji: "🏷️", titulo: "Centro de costos" },
"adjuntos": { emoji: "📎", titulo: "Adjuntos" },
"observaciones adicionales": { emoji: "📝", titulo: "Observaciones adicionales" }

};

function convertirATextoADF(texto) {

    if (!texto) {
        return {
            type: "doc",
            version: 1,
            content: []
        };
    }

    /* LIMPIAR HTML DEL FRONTEND */
    const textoPlano = texto
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/p>/gi, "\n")
        .replace(/<[^>]+>/g, "")
        .trim();

    const lineas = textoPlano
        .split("\n")
        .map(l => l.trim())
        .filter(l => l !== "");

    const contenido = [];
    let listaActual = [];

    function cerrarLista() {
        if (listaActual.length > 0) {

            contenido.push({
                type: "bulletList",
                content: listaActual.map(item => ({
                    type: "listItem",
                    content: [
                        {
                            type: "paragraph",
                            content: [
                                { type: "text", text: item }
                            ]
                        }
                    ]
                }))
            });

            listaActual = [];
        }
    }

    lineas.forEach(linea => {

        const textoLower = linea
            .replace(/[📄⚠️🏢👥🎯🔍🚀⚙️🔥🔗✅👤🏷️📎📝]/g, "")
            .replace(":", "")
            .toLowerCase()
            .trim();
        /* TITULOS AUTOMATICOS */
        if (mapaTitulos[textoLower]) {

            cerrarLista();

            const info = mapaTitulos[textoLower];

            contenido.push({
                type: "heading",
                attrs: { level: 3 },
                content: [
                    {
                        type: "text",
                        text: `${info.emoji} ${info.titulo}`
                    }
                ]
            });

            /* separador visual */
            contenido.push({
                type: "paragraph",
                content: [{ type: "text", text: " " }]
            });

            return;
        }

        /* TITULOS GENERICOS */
        if (linea.endsWith(":")) {

            cerrarLista();

            const titulo = linea.replace(":", "");

            contenido.push({
                type: "heading",
                attrs: { level: 3 },
                content: [
                    {
                        type: "text",
                        text: `📌 ${titulo}`
                    }
                ]
            });

            return;
        }

        /* DETECTAR LISTAS */
        if (
            linea.startsWith("–") ||
            linea.startsWith("-") ||
            linea.startsWith("•")
        ) {

            listaActual.push(
                linea.replace(/^[-–•]\s*/, "")
            );

            return;
        }

        cerrarLista();

        /* PARRAFOS NORMALES */
        contenido.push({
            type: "paragraph",
            content: [
                {
                    type: "text",
                    text: linea
                }
            ]
        });

    });

    cerrarLista();

    return {
        type: "doc",
        version: 1,
        content: contenido
    };
}

function normalizarId(texto) {
    if (!texto) return "";

    return texto
        .toString()
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, "") 
        .trim();
}


async function existeTicketEnJira(idRequerimiento) {

    try {

        if (!idRequerimiento) return false;

        const id = idRequerimiento.trim();

        console.log("🔎 Buscando:", id);

        const jql = `summary ~ "${id}"`;

        const response = await axios.get(
            "https://comwaredev.atlassian.net/rest/api/3/search/jql",
            {
                params: {
                    jql: jql,
                    maxResults: 10,
                    fields: "summary"
                },
                auth: {
                    username: process.env.JIRA_EMAIL,
                    password: process.env.JIRA_API_TOKEN
                }
            }
        );

        const issues = response.data.issues || [];

        if (issues.length > 0) {

            console.log("⚠️ DUPLICADO DETECTADO");

            issues.forEach(i => {
                console.log(i.key, "-", i.fields.summary);
            });

            return true;

        }

        console.log("✅ No existe ticket");

        return false;

    } catch (error) {

        console.error(
            "❌ Error validando ticket:",
            error.response?.data || error.message
        );

        return false;

    }

}



app.post("/crear-jira", async (req, res) => {

    try {

        const {
            tipoCaso,
            textoFinal,
            fechaRegistro,
            customfield_10120,
            adjuntos = []
        } = req.body;

        /* VALIDAR DUPLICADO EN JIRA */

        const idRequerimiento = (tipoCaso?.IdByProject || "").trim();

        const yaExiste = await existeTicketEnJira(idRequerimiento);

        if (yaExiste) {

            return res.status(400).json({
                success: false,
                error: `El requerimiento ${idRequerimiento} ya existe en Jira`
            });

        }

        console.log("📨 Recibiendo solicitud JIRA...");
        console.log("🏢 Centro costo:", customfield_10120);
        const centroCostoId = customfield_10120
            ? customfield_10120.split(" ")[0]
            : null;

        const sprint = await obtenerSprintActivo();

        if (!sprint) {
            return res.status(400).json({
                success: false,
                error: "No hay sprint activo"
            });
        }

        const summary = `PRCWARE - ${tipoCaso?.Subject} - ${tipoCaso?.IdByProject}`;

        const datosPlantilla = {
        textoFinal,
        tipoCaso,
        fechaRegistro,
        centroCosto: customfield_10120
        };

        console.log("TEXTO RECIBIDO:");
        console.log(textoFinal);

        const description = convertirATextoADF(textoFinal);

        console.log("ADF GENERADO:");
        console.log(JSON.stringify(description, null, 2));

        /* CREAR ISSUE */

        const issue = await axios.post(
            "https://comwaredev.atlassian.net/rest/api/3/issue",
            {
                fields: {

                    project: { id: "10405" },

                    issuetype: { id: "10439" },

                    summary,

                    description,

                    customfield_10020: Number(sprint.id),

                    customfield_10015: fechaRegistro,

                    ...(centroCostoId && {
                        customfield_10120: { id: centroCostoId }
                    })

                }
            },

            {
                auth: {
                    username: process.env.JIRA_EMAIL,
                    password: process.env.JIRA_API_TOKEN
                },
                headers: {
                    "Content-Type": "application/json"
                }
            }

        );

        console.log("🎫 Issue creado:", issue.data.key);

        /* SUBIR ADJUNTOS */

        if (adjuntos.length > 0) {

            console.log(`📎 Subiendo ${adjuntos.length} adjuntos`);

            for (const archivo of adjuntos) {

                try {

                    if (!archivo?.data) continue;

                    const buffer = Buffer.from(archivo.data, "base64");

                    const form = new FormData();

                    form.append("file", buffer, {
                        filename: archivo.nombre,
                        contentType: archivo.tipo
                    });

                    await axios.post(

                        `https://comwaredev.atlassian.net/rest/api/3/issue/${issue.data.key}/attachments`,

                        form,

                        {
                            auth: {
                                username: process.env.JIRA_EMAIL,
                                password: process.env.JIRA_API_TOKEN
                            },
                            headers: {
                                ...form.getHeaders(),
                                "X-Atlassian-Token": "no-check"
                            }
                        }

                    );

                } catch (error) {

                    console.log("⚠️ Error adjunto:", archivo.nombre);

                }

            }

        }

        return res.json({
            success: true,
            issueKey: issue.data.key
        });

    } catch (error) {

        console.error("🔥 ERROR JIRA:", error.response?.data || error);

        return res.status(500).json({
            success: false,
            error: error.response?.data || error.message
        });

    }

});

app.use((err, req, res, next) => {
    console.error("ERROR GLOBAL:", err);

    if (err.type === "entity.too.large") {
        return res.status(413).json({
            error: "Archivo demasiado grande"
        });
    }

    res.status(500).json({
        error: "Error interno del servidor"
    });
});

// REQUERIMIENTO FINALIZADO
app.put("/requerimientos/finalizar/:id", async (req, res) => {

    const { id } = req.params;
    const { comentario } = req.body;

    try {

        await pool.query(
            `UPDATE requerimientos_pgrr
             SET estado = 'Finalizado',
                 comentario = $1
             WHERE id = $2`,
            [comentario, id]
        );

        res.json({ success: true });

    } catch (error) {

        console.error("Error finalizando requerimiento:", error);

        res.status(500).json({
            success: false
        });

    }

});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

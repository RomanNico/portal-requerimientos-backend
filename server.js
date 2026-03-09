require("dotenv").config();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const express = require("express");

const { Pool } = require("pg");
const bcrypt = require("bcrypt");
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
    origin: ["http://localhost:5173"],
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


// ─── LOGIN  ───────────────────────────────────────────────
app.post("/login", async (req, res) => {

    const { usuario, password } = req.body;

    console.log("Intento login:", usuario);

    try {

        const result = await pool.query(
            `SELECT * FROM usuarios_pgrr WHERE nombre_usuario = $1`,
            [usuario]
        );

        console.log("Usuarios encontrados:", result.rows.length);

        if (result.rows.length === 0) {
            console.log("Usuario no existe");
            return res.json({ success: false });
        }

        const user = result.rows[0];

        console.log("Hash BD:", user.contrasena);

        const passwordValida = await bcrypt.compare(password, user.contrasena);

        console.log("Password válida:", passwordValida);

        if (!passwordValida) {
            return res.json({ success: false });
        }

        res.json({
            success: true,
            usuario: user.nombre_usuario,
            rol: user.rol
        });

    } catch (error) {

        console.error("Error en login:", error);
        res.status(500).json({ success: false });

    }
});

// OBTENER PERFIL
app.get("/perfil/:usuario", async (req, res) => {

    const { usuario } = req.params;

    try {

        const result = await pool.query(
            `SELECT nombre_usuario, correo, centro_costo, genero
            FROM usuarios_pgrr 
            WHERE nombre_usuario = $1`,
            [usuario]
        );

        if (result.rows.length === 0) {
            return res.json({ success: false });
        }

        res.json({
            success: true,
            usuario: result.rows[0]
        });

    } catch (error) {

        console.error("Error obteniendo perfil:", error);
        res.status(500).json({ success: false });

    }
});

// CAMBIAR CONTRASEÑA
app.post("/cambiar-password", async (req, res) => {

    const { usuario, actual, nueva } = req.body;

    try {

        const result = await pool.query(
            `SELECT contrasena 
             FROM usuarios_pgrr 
             WHERE nombre_usuario = $1`,
            [usuario]
        );

        if (result.rows.length === 0) {
            return res.json({ success: false, message: "Usuario no encontrado" });
        }

        const hashGuardado = result.rows[0].contrasena;

        const passwordValida = await bcrypt.compare(actual, hashGuardado);

        if (!passwordValida) {
            return res.json({ success: false, message: "Contraseña actual incorrecta" });
        }

        const nuevoHash = await bcrypt.hash(nueva, 10);

        await pool.query(
            `UPDATE usuarios_pgrr 
             SET contrasena = $1 
             WHERE nombre_usuario = $2`,
            [nuevoHash, usuario]
        );

        res.json({ success: true });

    } catch (error) {

        console.error("Error cambiando contraseña:", error);
        res.status(500).json({ success: false });

    }
});

// ─── NOVA  ───────────────────────────────────────────────

let novaToken = null;
let tokenExpira = 0;

async function obtenerTokenNova() {
    if (novaToken && Date.now() < tokenExpira) {
        return novaToken;
    }

    const loginResponse = await axios.post(
        "https://api-backend-service.comware.com.co:3026/api/auth/login",
        {
            username: process.env.NOVA_USER,
            password: process.env.NOVA_PASS,
            captcha: "1"
        }
    );

    novaToken = loginResponse.data.token;

    tokenExpira = Date.now() + (50 * 60 * 1000);

    return novaToken;
}


app.post("/api/nova", upload.array("files"), async (req, res) => {
    try {

        const { message, threadId, channel = "web" } = req.body;

        if (!threadId) {
            return res.status(400).json({ error: "threadId es obligatorio" });
        }

        if (!adjuntosPorThread[threadId]) {
            adjuntosPorThread[threadId] = [];
        }

        if (req.files && req.files.length > 0) {
            const nuevosAdjuntos = req.files.map(file => ({
                nombre: file.originalname,
                tipo: file.mimetype,
                data: file.buffer.toString("base64")
            }));

            adjuntosPorThread[threadId].push(...nuevosAdjuntos);
        }

        const token = await obtenerTokenNova();

        let reply = "Sin respuesta del asistente.";

        try {
            const novaResponse = await axios.post(
                "https://api-backend-service.comware.com.co:3026/api/sam-assistant/user-question-bp/4280d8c1-1022-4f44-bd05-d1d5dd3bd66c",
                {
                    question: message,
                    threadId,
                    channel
                },
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json"
                    },
                    timeout: 60000
                }
            );

            reply =
                novaResponse.data.isLastContent ||
                novaResponse.data.reply ||
                novaResponse.data.mensaje ||
                reply;

        } catch (novaError) {
            console.error("Error llamando Nova:", novaError.message);
            reply = "⚠️ Nova no respondió, pero los adjuntos fueron recibidos.";
        }

        const adjuntos = adjuntosPorThread[threadId] || [];

        return res.json({
            reply,
            adjuntos: adjuntosPorThread[threadId] || []
        });

    } catch (error) {
        console.error("ERROR GENERAL NOVA:", error);
        return res.status(500).json({
            error: "Error interno del servidor"
        });
    }
});

// ─── REQUERIMIENTOS ───────────────────────────────────────────

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
function convertirATextoADF(texto) {

    const lineas = texto.split("\n").map(l => l.trim()).filter(l => l !== "");

    const contenido = [];

    lineas.forEach(linea => {

        /* TITULOS */
        if (linea.endsWith(":")) {

            contenido.push({
                type: "heading",
                attrs: { level: 3 },
                content: [{ type: "text", text: linea.replace(":", "") }]
            });

            return;
        }

        /* LISTAS */
        if (linea.startsWith("–") || linea.startsWith("-")) {

            contenido.push({
                type: "bulletList",
                content: [
                    {
                        type: "listItem",
                        content: [
                            {
                                type: "paragraph",
                                content: [
                                    {
                                        type: "text",
                                        text: linea.replace(/^[-–]\s*/, "")
                                    }
                                ]
                            }
                        ]
                    }
                ]
            });

            return;
        }

        /* PARRAFOS */
        contenido.push({
            type: "paragraph",
            content: [{ type: "text", text: linea }]
        });

    });

    return {
        type: "doc",
        version: 1,
        content: contenido
    };

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

        const summary = `[MANAGER] ${tipoCaso?.Subject || "REQ"} - ${tipoCaso?.IdByProject || ""}`;

        const textoPlano = textoFinal
            ?.replace(/<br\s*\/?>/gi, "\n")
            ?.replace(/<\/p>/gi, "\n")
            ?.replace(/<[^>]+>/g, "")
            ?.trim();

        const description = convertirATextoADF(textoPlano);

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

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
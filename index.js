const express = require("express")
const { createConnection } = require("mysql2/promise");
const cors = require("cors");
require('dotenv').config();
const app = express()

const port = process.env.PORT || 3001

app.use(express.json());
app.use(cors());

async function createMysqlConn() {
    return await createConnection({
        host: process.env.HOST,
        user: process.env.USER,
        password: process.env.PASSWORD,
        database: process.env.DATABASE
    });
}

app.post("/api/login", async (req, res) => { 
    const { email, senha } = req.body; 

    const conn = await createMysqlConn()

    const query = `SELECT * 
                     FROM users 
                    WHERE email = ? 
                      AND senha = ?`
    const [getLogin] = await conn.execute(query, [email, senha]) 
    if(getLogin.length == 1){ 

        res.json({login: true, nome: getLogin[0].nome})

    } else if(getLogin.length == 0) {
        const query = `SELECT * 
                         FROM users 
                        WHERE email = ?`
        const [getToast] = await conn.execute(query, [email, senha])
        
        if(getToast.length == 1) {
            res.json({login: false, email: true}) 
        } else {
            res.json({login: false, email: false}) 
        } 
    }
});

app.post("/api/cadastrar", async(req, res) => {
    const { email, nome, senha } = req.body; 
    const conn = await createMysqlConn()

    const select = `SELECT email FROM users WHERE email = ?`
    const [verifExiste] = await conn.execute(select, [email]) 
    if(verifExiste.length == 1) {
        res.json({created: false, jaExiste: true}) 
    } else {
        try {
            const createUser = `INSERT INTO autopartes.users (email, nome, senha) VALUES (?, ?, ?)`
            await conn.execute(createUser, [email, nome, senha])
            res.json({created: true, jaExiste: false})  
        } catch (e) { 
            res.json({created: false, jaExiste: false}) 
        }
    }
})

app.post("/api/verificarLogin", async(req, res) => {
    const { email, nome, senha } = req.body;  
    const conn = await createMysqlConn()

    const select = `SELECT senha FROM users WHERE email = ?`
    const [pegaSenha] = await conn.execute(select, [email]) 

    if(pegaSenha.length == 1) {
        res.json({login: true, senha: pegaSenha[0].senha}) 
    } else { 
        res.json({login: false, senha: false})
    }
})

app.get('/', (req, res) => {
    res.send()
})

app.listen(port, () => {console.log("Server on")})
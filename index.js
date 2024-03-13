const express = require("express");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const { createConnection } = require("mysql2/promise");
const cors = require("cors");
require("dotenv").config();
const app = express();

const port = process.env.PORT || 3001;

app.use(express.json());
app.use(cors());

async function hashPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds);
  return hash;
}

async function createMysqlConn() {
  return await createConnection({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
  });
}

app.post("/api/login", async (req, res) => {
  const { email, senha } = req.body;

  const conn = await createMysqlConn();

  const query = `SELECT * 
                     FROM users 
                    WHERE email = ?`;
  const [getLogin] = await conn.execute(query, [email]);

  if (getLogin[0]?.senha) {
    try {
      bcrypt.compare(senha, getLogin[0].senha, (err, result) => {
        if (result) {
          res.json({ login: true, nome: getLogin[0].nome });
        } else {
          res.json({ login: false, email: true });
        }
      });
    } catch (e) {
      res.json({ login: false, email: true });
    }
  } else if (getLogin.length == 0) {
    try {
      const query = `SELECT * 
                             FROM users 
                            WHERE email = ?`;
      const [getToast] = await conn.execute(query, [email]);

      if (getToast.length == 1) {
        res.json({ login: false, email: true });
      } else {
        res.json({ login: false, email: false });
      }
    } catch (e) {
      res.json({ login: false, email: true });
    }
  }
});

app.post("/api/cadastrar", async (req, res) => {
  const { email, nome, senha } = req.body;
  const conn = await createMysqlConn();

  const select = `SELECT email FROM users WHERE email = ?`;
  const [verifExiste] = await conn.execute(select, [email]);
  if (verifExiste[0]?.email) {
    res.json({ created: false, jaExiste: true });
  } else {
    try {
      let hash = await hashPassword(senha);
      const createUser = `INSERT INTO autopartes.users (email, nome, senha) VALUES (?, ?, ?)`;
      await conn.execute(createUser, [email, nome, hash]);
      res.json({ created: true, jaExiste: false, senha: hash });
    } catch (e) {
      res.json({ created: false, jaExiste: false });
    }
  }
});

app.post("/api/verificarLogin", async (req, res) => {
  const { email, senha } = req.body;
  const conn = await createMysqlConn();

  const select = `SELECT senha FROM users WHERE email = ?`;
  const [pegaSenha] = await conn.execute(select, [email]);

  if (pegaSenha[0]?.senha) { 
    if (pegaSenha[0]?.senha == senha) {
      res.json({ login: true, senha: pegaSenha[0].senha });
    } else {
      res.json({ login: false, senha: false });
    }
  } else {
    res.json({ login: false });
  }
});

app.post("/api/mudarNome", async (req, res) => {
  const { email, novoNome } = req.body;
  const conn = await createMysqlConn();

  try {
    const uptadeNome = `UPDATE users SET nome = ? WHERE email = ?;`;
    await conn.execute(uptadeNome, [novoNome, email]);
  } catch (e) {
    console.log(e);
  } finally {
    res.json("");
  }
});

app.post("/api/alterarsenha", async (req, res) => {
  const { email, senha, cEmailAt, cSenhaAt, cSenhaCo, cSenhaNo } = req.body;
  const conn = await createMysqlConn();
  const hashNovaSenha = await hashPassword(cSenhaNo);
  try { 
    bcrypt.compare(cSenhaAt, senha, async(err, result) => { 
      if (!result) {   
        res.json({ resposta: 0 }); // Senha inválida!
      } else { 
          const uptadeNome = `UPDATE users SET senha = ? WHERE email = ?;`;
          await conn.execute(uptadeNome, [hashNovaSenha, email]);
          res.json({ resposta: 1, senhaNova: hashNovaSenha }) // Senha alterada! 
      }
  }); 

  } catch (e) { 
    console.log(e);
    res.json({ resposta: -1 }) //Não foi possivel continuar!
  } 
});

app.post("/api/retornacategorias", async (req, res) => { 
  const conn = await createMysqlConn(); 
  try {   
    const sqlSel = "SELECT * FROM categorias"
    const [categorias] = await conn.execute(sqlSel)
    res.json({ categorias})
  } catch (e) { 
    console.log(e);
    res.json({ categorias: -1 }) //Não foi possivel continuar!
  } 
});

app.post("/api/retornaestados", async (req, res) => { 
  const conn = await createMysqlConn(); 
  try {   
    const sqlSel = "SELECT * FROM estados"
    const [estados] = await conn.execute(sqlSel) 
    res.json({ estados })
  } catch (e) {  
    res.json({ estados: -1 }) //Não foi possivel continuar!
  } 
});

app.get("/", (req, res) => {
  res.send();
});

app.listen(port, () => {
  console.log("Server on");
});

const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require('body-parser');
const saltRounds = 10;
const { createConnection } = require("mysql2/promise");
const cors = require("cors");
require("dotenv").config();
const app = express();
const fs = require("fs");
const path = require('path');    
const fileUpload = require('express-fileupload');
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

const port = process.env.PORT || 3001;

app.use(express.json());
app.use(fileUpload())
app.use(cors()); 
  
async function hashPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds);
  return hash;
}
 
async function salvarImagemBase64(base64String, lastId) {
  try {
    const conn = await createMysqlConn(); 
    const imageBuffer = Buffer.from(base64String, 'base64');
 
    const insertImageQuery = 'INSERT INTO imagenspost (id, imagem) VALUES (?, ?)';
    await conn.execute(insertImageQuery, [lastId, imageBuffer]); 
  } catch (error) {
    console.error('Erro ao salvar imagem no banco de dados:', error);
  } 
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
    bcrypt.compare(cSenhaAt, senha, async (err, result) => {
      if (!result) {
        res.json({ resposta: 0 }); // Senha inválida!
      } else {
        const uptadeNome = `UPDATE users SET senha = ? WHERE email = ?;`;
        await conn.execute(uptadeNome, [hashNovaSenha, email]);
        res.json({ resposta: 1, senhaNova: hashNovaSenha }); // Senha alterada!
      }
    });
  } catch (e) {
    console.log(e);
    res.json({ resposta: -1 }); //Não foi possivel continuar!
  }
});

app.post("/api/retornacategorias", async (req, res) => {
  const conn = await createMysqlConn();
  try {
    const sqlSel = "SELECT * FROM categorias";
    const [categorias] = await conn.execute(sqlSel);
    res.json({ categorias });
  } catch (e) {
    console.log(e);
    res.json({ categorias: -1 }); //Não foi possivel continuar!
  }
});

app.post("/api/retornaestados", async (req, res) => {
  const conn = await createMysqlConn();
  try {
    const sqlSel = "SELECT * FROM estados";
    const [estados] = await conn.execute(sqlSel);
    res.json({ estados });
  } catch (e) {
    res.json({ estados: -1 }); //Não foi possivel continuar!
  }
});

app.post("/api/retornafretes", async (req, res) => {
  const conn = await createMysqlConn();
  try {
    const sqlSel = "SELECT * FROM fretes";
    const [fretes] = await conn.execute(sqlSel);
    res.json({ fretes });
  } catch (e) {
    res.json({ fretes: -1 }); //Não foi possivel continuar!
  }
});

app.post("/api/retornaimagem", async (req, res) => { 
  const { email } = req.body;
  try {
    const conn = await createMysqlConn();
    const query = "SELECT imagem FROM imagensperfil WHERE email = ?";
    const [rows] = await conn.execute(query, [email]);
    if (rows.length > 0 && rows[0].imagem) {
      const imagemBase64 = Buffer.from(rows[0].imagem, "binary").toString("base64");
      res.send(imagemBase64);  
    } else {
      res.status(404).json({ error: "Imagem não encontrada" });
    }
  } catch (error) {
    console.error("Erro ao buscar imagem do perfil:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/mudarfotoperfil", async (req, res) => { 
  try {
    // Verifica se foi enviado um arquivo
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
    }

    const conn = await createMysqlConn();
     
    const email = req.body.email;
    
    const file = req.files.file; 

    const imageBuffer = Buffer.from(file.data, 'base64'); // Acessa a propriedade .data do arquivo
    
    const sqlSel = "SELECT count(email) count FROM imagensperfil WHERE email = ?";
    const [counter] = await conn.execute(sqlSel, [email]);

    if(counter[0].count == 1){
      const insertImageQuery = 'UPDATE imagensperfil SET imagem = ? WHERE email = ?';
      await conn.execute(insertImageQuery, [imageBuffer, email]);
    } else {
      const insertImageQuery = 'INSERT INTO imagensperfil (email, imagem) VALUES (?, ?)';
      await conn.execute(insertImageQuery, [email, imageBuffer ]);
    }  

    console.log('Imagem salva com sucesso no banco de dados.');
    res.status(200).json({ message: 'Imagem salva com sucesso no banco de dados.' });
  } catch (error) {
    console.error('Erro ao salvar imagem no banco de dados:', error);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post("/api/createpostitem", async (req, res) => {
  const {
    email,
    senha,
    images,
    titlePost,
    descriPost,
    corPost,
    skuPost,
    catSel,
    conSel,
    freSel,
  } = req.body;
  const conn = await createMysqlConn();
  
  try {
    const createPost = `INSERT INTO posts (titulo, descri, cor, sku, categoria, estado, frete, tipo) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    await conn.execute(createPost, [
      titlePost,
      descriPost,
      corPost,
      skuPost,
      catSel,
      conSel,
      freSel,
      1,
    ]);

    const selLastId = `SELECT last_insert_id() id FROM posts`;
    const [arrayRowid] = await conn.execute(selLastId);
    const lastId = arrayRowid[0].id; 

    const updateUsersPost = `INSERT INTO usersposts (id, email) VALUES (?, ?)`;
    await conn.execute(updateUsersPost, [lastId, email]);

    images.forEach(async (imagem) => {
      await salvarImagemBase64(imagem, lastId)
    });
  } catch (e) {
    console.log(e);
  } finally {
    res.json("");
  }
}); 


app.get("/", (req, res) => {
  res.send();
});

app.listen(port, () => {
  console.log("Server on");
});

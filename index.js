const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const saltRounds = 10;
const { createConnection } = require("mysql2/promise");
const cors = require("cors");
require("dotenv").config();
const app = express();
const fs = require("fs");
const path = require("path");
const fileUpload = require("express-fileupload");
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

const port = process.env.PORT || 3001;

app.use(express.json());
app.use(fileUpload());
app.use(cors());

async function hashPassword(password) {
    const hash = await bcrypt.hash(password, saltRounds);
    return hash;
}

function retornaStringAlgoritmo(str, id, tam = 20) {
    let strArr = str.split(",");

    if ((strArr.length === 1 && strArr[0] === "") || strArr[0] === String(id)) {
        return String(id);
    }

    strArr = strArr.filter((elemento) => elemento !== String(id).trim());
    str = strArr.join(",");

    if (strArr.length >= tam) {
        strArr.pop();
        strArr.unshift(id);
        return strArr.join(",");
    }

    return id + "," + str;
}

function retornaPrecoFormatado(preco) {
    let precoVal = preco;

    if (preco === "0") {
        return preco;
    }

    if (precoVal.split(",")[1]) {
        const partes = precoVal.split(",");
        if (partes[1].length === 1) {
            return precoVal + "0";
        }
    }
    if (!precoVal.includes(",")) {
        return precoVal + ",00";
    }
    if (precoVal[precoVal.length - 1] === ",") {
        return precoVal + "00";
    }

    return precoVal;
}

async function salvarImagemBase64(base64String, lastId, i) {
    try {
        const conn = await createMysqlConn();
        const imageBuffer = Buffer.from(base64String.data, "base64");

        const insertImageQuery =
            "INSERT INTO imagenspost (id, imagem, ordem) VALUES (?, ?, ?)";
        await conn.execute(insertImageQuery, [lastId, imageBuffer, i]);
    } catch (error) {
        console.error("Erro ao salvar imagem no banco de dados:", error);
    }
}

async function createMysqlConn() {
    return await createConnection({
        host: process.env.HOST,
        user: process.env.USER,
        password: process.env.PASSWORD,
        database: process.env.DATABASE,
        connectionLimit: 0,
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
                    res.json({
                        login: true,
                        nome: getLogin[0].nome,
                        id: getLogin[0].id,
                        senha: getLogin[0].senha,
                    });
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
    try {
        const { email, nome, senha } = req.body;
        const conn = await createMysqlConn();

        const select = `SELECT * FROM users WHERE email = ?`;
        const [verifExiste] = await conn.execute(select, [email]);
        if (verifExiste[0]?.email) {
            res.json({ created: false, jaExiste: true });
        } else {
            let hash = await hashPassword(senha);
            const createUser = `INSERT INTO autopartes.users (email, nome, senha) VALUES (?, ?, ?)`;
            await conn.execute(createUser, [email, nome, hash]);

            const selLastId = `SELECT last_insert_id() id FROM users `;
            const id = await conn.execute(selLastId);

            res.json({
                created: true,
                jaExiste: false,
                senha: hash,
                id: id[0].id,
            });
        }
    } catch (e) {
        console.log(e);
        res.json({ created: false, jaExiste: false });
    }
});

app.post("/api/verificarLogin", async (req, res) => {
    const { email, senha } = req.body;
    const conn = await createMysqlConn();

    const select = `SELECT senha FROM users WHERE email = ?`;
    const [pegaSenha] = await conn.execute(select, [email]);
    if (senha === pegaSenha[0]?.senha) {
        res.json({ login: true, senha: pegaSenha[0].senha });
    } else {
        res.json({ login: false, senha: false });
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
        res.status(200).json("");
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
        const sqlSel = `SELECT id, codigo, descri FROM categorias`;
        const [categorias] = await conn.execute(sqlSel);
        res.json({ categorias });
    } catch (e) {
        console.log(e);
        res.json({ categorias: -1 }); //Não foi possivel continuar!
    }
});

app.post("/api/returnImagemCategoria", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { id } = req.body;
        const query = "SELECT imagem FROM categorias WHERE id = ?";
        const [rows] = await conn.execute(query, [id + 1]);
        const row = rows[0];
        if (rows.length > 0 && row.imagem) {
            const imagemBase64 = Buffer.from(row.imagem, "binary").toString(
                "base64"
            );
            res.send(imagemBase64);
        } else {
            res.status(404).json({ error: "Imagem não encontrada" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
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
            const imagemBase64 = Buffer.from(rows[0].imagem, "binary").toString(
                "base64"
            );
            res.send(imagemBase64);
        } else {
            res.json(null);
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/returnHomeRecomendados", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const query = `SELECT posts.id, 
                    CONCAT(
                     LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 56, 53, CHAR_LENGTH(posts.titulo))),
           IF(CHAR_LENGTH(posts.titulo) > 56, '...', '')
                     ) AS titulo, 
                          posts.descri,  
                          posts.preco,
                          fretes.descriResumida
                     FROM posts
                LEFT JOIN fretes on fretes.id = posts.frete `;
        const [rows] = await conn.execute(query);
        if (rows.length > 0) {
            res.send(rows);
        } else {
            res.json("");
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/returnhomehistorico", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { email } = req.body;

        const selHis = `SELECT historico FROM users WHERE email = ?`;
        const [row] = await conn.execute(selHis, [email]);

        const query = `SELECT posts.id, 
                    CONCAT(
                     LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 56, 53, CHAR_LENGTH(posts.titulo))),
           IF(CHAR_LENGTH(posts.titulo) > 56, '...', '')
                     ) AS titulo, 
                          posts.descri,  
                          posts.preco,
                          fretes.descriResumida
                     FROM posts
                LEFT JOIN fretes on fretes.id = posts.frete
                WHERE posts.id IN (${row[0].historico}) `;
        const [rows] = await conn.execute(query);
        if (rows.length > 0) {
            res.send(rows);
        } else {
            res.json("");
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/returnImagemCapa", async (req, res) => {
    const { id } = req.body;
    try {
        const conn = await createMysqlConn();
        const query =
            "SELECT imagem FROM imagenspost WHERE ordem = ? AND id = ? LIMIT 1";
        const [rows] = await conn.execute(query, [0, id]);
        if (rows.length > 0 && rows[0].imagem) {
            const imagemBase64 = Buffer.from(rows[0].imagem, "binary").toString(
                "base64"
            );
            res.send(imagemBase64);
        } else {
            res.status(404).json({ error: "Imagem não encontrada" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/returnImagensProduto", async (req, res) => {
    const { id } = req.body;
    try {
        const conn = await createMysqlConn();
        const query =
            "SELECT imagem FROM imagenspost WHERE id = ? ORDER BY ordem";
        let [rows] = await conn.execute(query, [id]);
        if (rows.length > 0 && rows[0].imagem) {
            rows.forEach((element, i) => {
                rows[i].imagem = Buffer.from(element.imagem, "binary").toString(
                    "base64"
                );
            });
            res.send(rows);
        } else {
            res.status(404).json({ error: "Imagem não encontrada" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/mudarfotoperfil", async (req, res) => {
    try {
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).json({ error: "Nenhum arquivo enviado." });
        }

        const conn = await createMysqlConn();

        const email = req.body.email;

        const file = req.files.file;

        const imageBuffer = Buffer.from(file.data, "base64");

        const sqlSel =
            "SELECT count(email) count FROM imagensperfil WHERE email = ?";
        const [counter] = await conn.execute(sqlSel, [email]);

        if (counter[0].count == 1) {
            const insertImageQuery =
                "UPDATE imagensperfil SET imagem = ? WHERE email = ?";
            await conn.execute(insertImageQuery, [imageBuffer, email]);
        } else {
            const insertImageQuery =
                "INSERT INTO imagensperfil (email, imagem) VALUES (?, ?)";
            await conn.execute(insertImageQuery, [email, imageBuffer]);
        }

        res.status(200).json({
            message: "Imagem salva com sucesso no banco de dados.",
        });
    } catch (error) {
        console.error("Erro ao salvar imagem no banco de dados:", error);
        res.status(500).json({ error: "Erro interno do servidor." });
    }
});

app.post("/api/createpostitem", async (req, res) => {
    const { file0, file1, file2, file3 } = req.files;

    const {
        titlePost,
        descriPost,
        corPost,
        skuPost,
        catSel,
        conSel,
        freSel,
        precoPost,
        precoFreteSel,
        email,
    } = req.body;
    const conn = await createMysqlConn();

    try {
        if (freSel === 1) {
            precoFreteSel = 0;
        }

        const precoPostOfc = retornaPrecoFormatado(precoPost);
        const precoFreteSelOfc = retornaPrecoFormatado(precoFreteSel);

        const createPost = `INSERT INTO posts (email, titulo, descri, preco, cor, sku, categoria, estado, frete, tipo, avaliacao, vendas, custoFrete) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        await conn.execute(createPost, [
            email,
            titlePost,
            descriPost,
            precoPostOfc,
            corPost,
            skuPost,
            catSel,
            conSel,
            freSel,
            1,
            0,
            0,
            precoFreteSelOfc,
        ]);

        const selLastId = `SELECT last_insert_id() id FROM posts`;
        const [arrayRowid] = await conn.execute(selLastId);
        const lastId = arrayRowid[0].id;

        if (file0) {
            await salvarImagemBase64(file0, lastId, 0);
        }
        if (file1) {
            await salvarImagemBase64(file1, lastId, 1);
        }
        if (file2) {
            await salvarImagemBase64(file2, lastId, 2);
        }
        if (file3) {
            await salvarImagemBase64(file3, lastId, 3);
        }
    } catch (e) {
        console.log(e);
    } finally {
        res.json("");
    }
});

app.post("/api/returnProduto", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const id = req.body.id;
        const query = `SELECT posts.id, 
                                posts.titulo, 
                                posts.descri, 
                                posts.preco, 
                                posts.cor, 
                                posts.sku, 
                                posts.avaliacao, 
                                posts.vendas, 
                                posts.custoFrete, 
                                posts.dataCriacao, 
                                posts.frete, 
                                categorias.descri categoria, 
                                estados.descri estado,  
                                users.id sellerId,                             
                                users.email, 
                                users.nome sellerUsername, 
                                users.vendas sellerVendas, 
                                users.avaliacao sellerAvaliacao,  
                                TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) AS sellerDataCriacao
                                FROM posts 
                                INNER JOIN categorias ON categorias.id = posts.categoria 
                                INNER JOIN estados ON estados.id = posts.estado  
                                INNER JOIN users ON users.email = posts.email
                                WHERE posts.id = ?`;
        const [row] = await conn.execute(query, [id]);
        if (row.length > 0) {
            res.json(row);
        } else {
            res.status(500).json({ error: "Erro interno do servidor" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/retornaSellerInfos", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { id } = req.body;
        const query = `SELECT email, nome, vendas, avaliacao, TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) dataCriacao FROM users WHERE id = ? LIMIT 1`;
        const [rows] = await conn.execute(query, [id]);
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(500).json({ error: "Erro interno do servidor" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});
app.post("/api/retornaSellerData", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { id } = req.body;
        const query = `SELECT posts.id, 
                         CONCAT(
                           LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 56, 53, CHAR_LENGTH(posts.titulo))),
                 IF(CHAR_LENGTH(posts.titulo) > 56, '...', '')
                           ) AS titulo, 
                                posts.descri, 
                                posts.preco, 
                                posts.cor, 
                                posts.sku, 
                                posts.avaliacao, 
                                posts.vendas, 
                                posts.custoFrete, 
                                posts.dataCriacao, 
                                posts.frete, 
                                categorias.descri categoria, 
                                estados.descri estado,  
                                users.id sellerId,                             
                                users.email,
                                users.nome sellerUsername, 
                                users.vendas sellerVendas, 
                                users.avaliacao sellerAvaliacao,  
                                fretes.descriResumida,
                                TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) AS sellerDataCriacao
                                FROM posts 
                                INNER JOIN categorias ON categorias.id = posts.categoria 
                                INNER JOIN estados ON estados.id = posts.estado  
                                INNER JOIN users ON users.email = posts.email
                                LEFT JOIN fretes ON fretes.id = posts.frete
                                WHERE users.id = ?
                                LIMIT 80`;
        const [rows] = await conn.execute(query, [id]);
        if (rows.length > 0) {
            res.json(rows);
        } else {
            res.status(500).json({ error: "Erro interno do servidor" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/createalgoritmo", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { id, email, table, tam } = req.body;

        const query = `SELECT ${table} alg FROM users WHERE email = ?`;
        const [row] = await conn.execute(query, [email]);

        const strAlg = retornaStringAlgoritmo(row[0].alg || "", Number(id), 20);

        const alterTable = `UPDATE users SET ${table} = ? WHERE email = ?`;
        await conn.execute(alterTable, [strAlg, email]);

        res.json("true");
    } catch (error) {
        console.error("Erro ao criar algoritmo:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/criaRelacionamentoCarrinho", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { id, idPost } = req.body;

        const sel = `SELECT idUser FROM cart WHERE idUser = ? AND idPost = ? LIMIT 1`;
        const [verifExiste] = await conn.execute(sel, [id, idPost]);

        if (verifExiste.length == 0) {
            const alterTable = `INSERT INTO cart (idUser, IdPost, quantidade) VALUES (?, ?, ?)`;
            await conn.execute(alterTable, [id, idPost, 1]);
            res.json({ created: true });
        } else {
            res.json({ created: false });
        }
    } catch (error) {
        console.error("Erro ao criar algoritmo:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/deletaRelacaoCarrinho", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { idUser, idPost } = req.body;

        const alterTable = `DELETE FROM cart WHERE idUser = ? AND idPost = ?`;
        await conn.execute(alterTable, [idUser, idPost]);

        res.status(200).json({ created: true });
    } catch (error) {
        console.error("Erro ao deletar item no carrinho:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/returnCarrinho", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { id } = req.body;

        const sel = `SELECT posts.id, 
                        CONCAT(
                        LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 50, 47, CHAR_LENGTH(posts.titulo))),
                IF(CHAR_LENGTH(posts.titulo) > 50, '...', '')
                        ) AS titulo, 
                            posts.descri, 
                            posts.preco, 
                            posts.cor, 
                            posts.sku, 
                            posts.avaliacao, 
                            posts.vendas, 
                            posts.custoFrete, 
                            posts.dataCriacao, 
                            posts.frete, 
                            categorias.descri categoria, 
                            estados.descri estado,  
                            users.id sellerId,                             
                            users.email,
                            users.nome sellerUsername, 
                            users.vendas sellerVendas, 
                            users.avaliacao sellerAvaliacao,  
                            fretes.descriResumida,
                            TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) AS sellerDataCriacao,
                            cart.quantidade 
                            FROM cart 
                INNER JOIN users ON users.id = cart.idUser
                INNER JOIN posts on posts.id = cart.idPost
                INNER JOIN categorias ON categorias.id = posts.categoria 
                INNER JOIN estados ON estados.id = posts.estado  
                INNER JOIN fretes ON fretes.id = posts.frete   
                WHERE cart.idUser = ?
                ORDER BY posts.titulo`;
        const [rows] = await conn.execute(sel, [id]);
        res.json(rows);
    } catch (error) {
        console.error("Erro ao retornar carrinho:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.post("/api/returnSearchList", async (req, res) => {
    try {
        const conn = await createMysqlConn();
        const { tipo, search } = req.body; 

        let sel = "";
        let arr = []
        //Pesquisas normais / diretas
        if (Number(tipo) === 0) {
            sel = `SELECT posts.id, 
                    CONCAT(
                    LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 50, 47, CHAR_LENGTH(posts.titulo))),
            IF(CHAR_LENGTH(posts.titulo) > 50, '...', '')
                    ) AS titulo, 
                        posts.descri, 
                        posts.preco, 
                        posts.cor, 
                        posts.sku, 
                        posts.avaliacao, 
                        posts.vendas, 
                        posts.custoFrete, 
                        posts.dataCriacao, 
                        posts.frete, 
                        categorias.descri categoria, 
                        estados.descri estado,  
                        users.id sellerId,                             
                        users.email,
                        users.nome sellerUsername, 
                        users.vendas sellerVendas, 
                        users.avaliacao sellerAvaliacao,  
                        fretes.descriResumida,
  TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) AS sellerDataCriacao, 
                 MATCH (titulo) AGAINST (? IN NATURAL LANGUAGE MODE) AS relevancia
                   FROM posts
             INNER JOIN categorias ON categorias.id = posts.categoria 
             INNER JOIN estados ON estados.id = posts.estado  
             INNER JOIN users ON users.email = posts.email
             INNER JOIN fretes ON fretes.id = posts.frete
           WHERE MATCH (titulo) AGAINST (? IN NATURAL LANGUAGE MODE)
               ORDER BY relevancia DESC, 
                        datacriacao DESC
                  LIMIT 80; `;
            
            arr = [search, search]
        } else if(Number(tipo) == 1) {
            sel = `SELECT posts.id, 
                 CONCAT(
                   LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 50, 47, CHAR_LENGTH(posts.titulo))),
         IF(CHAR_LENGTH(posts.titulo) > 50, '...', '')
                   ) AS titulo, 
                        posts.descri, 
                        posts.preco, 
                        posts.cor, 
                        posts.sku, 
                        posts.avaliacao, 
                        posts.vendas, 
                        posts.custoFrete, 
                        posts.dataCriacao, 
                        posts.frete, 
                        categorias.descri categoria, 
                        estados.descri estado,  
                        users.id sellerId,                             
                        users.email,
                        users.nome sellerUsername, 
                        users.vendas sellerVendas, 
                        users.avaliacao sellerAvaliacao,  
                        fretes.descriResumida,
  TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) AS sellerDataCriacao
                   FROM posts
             INNER JOIN categorias ON categorias.id = posts.categoria 
             INNER JOIN estados ON estados.id = posts.estado  
             INNER JOIN users ON users.email = posts.email
             INNER JOIN fretes ON fretes.id = posts.frete 
                  WHERE posts.categoria = (select id FROM categorias WHERE descri = ?)
               ORDER BY vendas DESC, 
                        dataCriacao DESC
                  LIMIT 80;`
            arr = [search]
        }

        const [rows] = await conn.execute(sel, arr);
        res.json(rows);
    } catch (error) {
        console.error("Erro ao retornar carrinho:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

app.get("/", (req, res) => {
    res.send();
});

app.listen(port, () => {
    console.log("Server on");
});

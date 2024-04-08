const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const saltRounds = 10;
const { createConnection } = require("mysql2/promise");
const cors = require("cors");
require("dotenv").config();
const app = express();
const fileUpload = require("express-fileupload");
app.use(bodyParser.json({ limit: "500mb" }));
app.use(bodyParser.urlencoded({ limit: "500mb", extended: true }));
const jab = require("./cryptography");

const port = process.env.PORT || 3001;

app.use(express.json());
app.use(fileUpload());
app.use(cors());

async function hashPassword(password) {
    const hash = await bcrypt.hash(password, saltRounds);
    return hash;
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

async function salvarImagemBase64(
    base64String,
    lastId,
    i,
    table = "imagenspost"
) {
    try {
        const conn = await createMysqlConn();
        const imageBuffer = Buffer.from(base64String.data, "base64");

        const insertImageQuery = `INSERT INTO ${table} (id, imagem, ordem) VALUES (?, ?, ?)`;
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
    console.log("lo");
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
    conn.end();
});

app.post("/api/cadastrar", async (req, res) => {
    console.log("ca");
    const conn = await createMysqlConn();
    try {
        const { email, nome, senha } = req.body;

        const select = `SELECT * FROM users WHERE email = ?`;
        const [verifExiste] = await conn.execute(select, [email]);
        if (verifExiste[0]?.email) {
            res.json({ created: false, jaExiste: true });
        } else {
            let hash = await hashPassword(senha);
            const createUser = `INSERT INTO autopartes.users (email, nome, senha) VALUES (?, ?, ?)`;
            await conn.execute(createUser, [email, nome, hash]);

            const selLastId = `SELECT last_insert_id() id FROM users LIMIT 1`;
            const [id] = await conn.execute(selLastId); 
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
    } finally {
        conn.end();
    }
});

app.post("/api/verificarLogin", async (req, res) => {
    console.log("ve");
    const { email, senha } = req.body;
    const conn = await createMysqlConn();

    const select = `SELECT senha FROM users WHERE email = ?`;
    const [pegaSenha] = await conn.execute(select, [email]);
    if (senha === pegaSenha[0]?.senha) {
        res.json({ login: true, senha: pegaSenha[0].senha });
    } else {
        res.json({ login: false, senha: false });
    }

    conn.end();
});

app.post("/api/mudarNome", async (req, res) => {
    console.log("mu");
    const { email, novoNome } = req.body;
    const conn = await createMysqlConn();

    try {
        const uptadeNome = `UPDATE users SET nome = ? WHERE email = ?;`;
        await conn.execute(uptadeNome, [novoNome, email]);
    } catch (e) {
        console.log(e);
    } finally {
        res.status(200).json("");
        conn.end();
    }
});

app.post("/api/alterarsenha", async (req, res) => {
    console.log("al");
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
    } finally {
        conn.end();
    }
});

app.post("/api/retornacategorias", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, codigo, descri FROM categorias`;
        const [categorias] = await conn.execute(sqlSel);
        res.json({ categorias });
    } catch (e) {
        console.log(e);
        res.json({ categorias: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaNome", async (req, res) => { 
    const conn = await createMysqlConn();

    try {
        const { id } = req.body
        const sqlSel = `SELECT nome FROM users WHERE id = ?`;
        const [nome] = await conn.execute(sqlSel, [id]);
        res.json(nome);
    } catch (e) {
        console.log(e);
        res.json({ nome: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});
app.post("/api/retornaCambios", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM cambios`;
        const [cambios] = await conn.execute(sqlSel);
        res.json({ cambios });
    } catch (e) {
        console.log(e);
        res.json({ cambios: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaCombustivel", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM combustiveis`;
        const [combustivel] = await conn.execute(sqlSel);
        res.json({ combustivel });
    } catch (e) {
        console.log(e);
        res.json({ combustivel: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaFinaisPlaca", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM finaisplaca`;
        const [finaisPlaca] = await conn.execute(sqlSel);
        res.json({ finaisPlaca });
    } catch (e) {
        console.log(e);
        res.json({ finaisPlaca: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaDirecao", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM direcoes`;
        const [direcoes] = await conn.execute(sqlSel);
        res.json({ direcoes });
    } catch (e) {
        console.log(e);
        res.json({ direcoes: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaPotencias", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM potencias`;
        const [potencias] = await conn.execute(sqlSel);
        res.json({ potencias });
    } catch (e) {
        console.log(e);
        res.json({ potencias: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaAnos", async (req, res) => {
    console.log("ret");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM anos`;
        const [anos] = await conn.execute(sqlSel);
        res.json({ anos });
    } catch (e) {
        console.log(e);
        res.json({ anos: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/returnMotivosDenuncia", async (req, res) => {
    console.log("rmd");
    const conn = await createMysqlConn();

    try {
        const sqlSel = `SELECT id, descri FROM motivosDenuncia`;
        const [motivos] = await conn.execute(sqlSel);

        res.json(motivos);
    } catch (e) {
        console.log(e);
        res.json({ resposta: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/returnDenuncias", async (req, res) => {
    console.log("rd");
    const conn = await createMysqlConn();

    try {
        const sqlSelAnun = `SELECT denuncias.id, 
                                motivosdenuncia.descri motivo, 
                                denuncias.descri,
                                idUser, 
                                (SELECT nome FROM users WHERE id = idUser) nome,
                                denuncias.email, 
                                idPost,  
                                denuncias.dataCriacao,
                                users.email emailAdo,
                                users.nome nomeAdo,
                                users.id idAdo
                           FROM denuncias 
                     INNER JOIN motivosdenuncia ON denuncias.motivoDenuncia = motivosdenuncia.id 
                     INNER JOIN users ON users.id = (SELECT id FROM users WHERE email = (SELECT email FROM posts WHERE id = denuncias.idPost))
                          WHERE situacao = 0
                            AND tipo = 0
                       ORDER BY dataCriacao`;
        const [anuncio] = await conn.execute(sqlSelAnun);

        const sqlSelVend = `SELECT denuncias.id, 
                                    motivosdenuncia.descri motivo, 
                                    denuncias.descri,
                                    idUser, 
                            (SELECT nome FROM users WHERE id = idUser) nome,
                                    denuncias.email, 
                                    idPost, 
                                    denuncias.dataCriacao,
                                    users.email emailAdo,
                                    users.nome nomeAdo,
                                    users.id idAdo
                               FROM denuncias 
                          INNER JOIN motivosdenuncia ON denuncias.motivoDenuncia = motivosdenuncia.id 
                         INNER JOIN users ON users.id = idPost
                              WHERE situacao = 0
                                AND tipo = 1
                           ORDER BY dataCriacao`;
        const [vendedor] = await conn.execute(sqlSelVend);

        const sqlSelSup = `SELECT denuncias.id, 
                                   motivosdenuncia.descri motivo, 
                                   denuncias.descri,
                                   idUser, 
                           (SELECT nome FROM users WHERE id = idUser) nome,
                                   denuncias.email,   
                                   denuncias.dataCriacao
                              FROM denuncias 
                        INNER JOIN motivosdenuncia ON denuncias.motivoDenuncia = motivosdenuncia.id  
                             WHERE situacao = 0
                               AND tipo = 2
                          ORDER BY dataCriacao`;
        const [suporte] = await conn.execute(sqlSelSup);

        res.json({ resposta: [anuncio, vendedor, suporte] });
    } catch (e) {
        console.log(e);
        res.json({ resposta: -1 });
    } finally {
        conn.end();
    }
});

app.post("/api/encerrarDenuncia", async (req, res) => {
    console.log("ed");
    const conn = await createMysqlConn();
    try {
        const { id } = req.body;
        const sqlAlt = `UPDATE denuncias SET situacao = 1 WHERE id = ?`;
        await conn.execute(sqlAlt, [id]);

        res.json({ sucesso: true });
    } catch (e) {
        console.log(e);
        res.json({ resposta: -1 });
    } finally {
        conn.end();
    }
});

app.post("/api/returnImagemCategoria", async (req, res) => {
    console.log("rim");
    const conn = await createMysqlConn();
    try {
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
    } finally {
        conn.end();
    }
});

app.post("/api/retornaestados", async (req, res) => {
    console.log("rest");
    const conn = await createMysqlConn();
    try {
        const sqlSel = "SELECT * FROM estados";
        const [estados] = await conn.execute(sqlSel);
        res.json({ estados });
    } catch (e) {
        res.json({ estados: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornafretes", async (req, res) => {
    console.log("refre");
    const conn = await createMysqlConn();
    try {
        const sqlSel = "SELECT * FROM fretes";
        const [fretes] = await conn.execute(sqlSel);
        res.json({ fretes });
    } catch (e) {
        res.json({ fretes: -1 }); //Não foi possivel continuar!
    } finally {
        conn.end();
    }
});

app.post("/api/retornaimagem", async (req, res) => {
    console.log("reima");
    const { email, id, porId } = req.body;
    const conn = await createMysqlConn();
     
    try {
        let emailOfc = email
        if(porId) {
            const selEmail = "SELECT email FROM users WHERE id = ?";
            const [emailSel] = await conn.execute(selEmail, [id]);
            emailOfc = emailSel[0].email
        }
        const query = "SELECT imagem FROM imagensperfil WHERE email = ?";
        const [rows] = await conn.execute(query, [emailOfc]);
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
    } finally {
        conn.end();
    }
});

app.post("/api/returnHomeRecomendados", async (req, res) => {
    console.log("rehore");
    const conn = await createMysqlConn();
    const { idUser } = req.body;
    try {
        const query = `SELECT posts.id, 
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
    MATCH (titulo) AGAINST ((SELECT GROUP_CONCAT(titulo SEPARATOR " ") FROM posts WHERE FIND_IN_SET(posts.id, (SELECT GROUP_CONCAT(idPost SEPARATOR ",") FROM historico WHERE idUser = ?)) > 0) IN NATURAL LANGUAGE MODE) AS relevancia
    FROM posts
INNER JOIN categorias ON categorias.id = posts.categoria 
INNER JOIN estados ON estados.id = posts.estado  
INNER JOIN users ON users.email = posts.email
INNER JOIN fretes ON fretes.id = posts.frete
WHERE MATCH (titulo) AGAINST ((SELECT GROUP_CONCAT(titulo SEPARATOR " ") FROM posts WHERE FIND_IN_SET(posts.id, (SELECT GROUP_CONCAT(idPost SEPARATOR ",") FROM historico WHERE idUser = ?)) > 0) IN NATURAL LANGUAGE MODE)
AND NOT EXISTS (
    SELECT 1 
    FROM historico 
    WHERE historico.idUser = 2 
    AND historico.idPost = posts.id
)
ORDER BY relevancia DESC, 
            datacriacao DESC
    LIMIT 20`;
        const [rows] = await conn.execute(query, [idUser, idUser]);
        if (rows.length > 0) {
            res.send(rows);
        } else {
            res.json("");
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/returnHomeDescubra", async (req, res) => {
    console.log("rehore");
    const conn = await createMysqlConn();
    const { email } = req.body;
    try {
        const query = `SELECT posts.id, 
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
                    WHERE posts.email != ?
                    ORDER BY RAND()
                        LIMIT 20`;
        const [rows] = await conn.execute(query, [email]);
        if (rows.length > 0) {
            res.send(rows);
        } else {
            res.json("");
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/returnhomehistorico", async (req, res) => {
    console.log("rehohi");
    const conn = await createMysqlConn();
    try {
        const { idUser } = req.body;

        const query = `SELECT 
                            posts.id, 
                            CONCAT(
                                LEFT(posts.titulo, IF(CHAR_LENGTH(posts.titulo) > 56, 53, CHAR_LENGTH(posts.titulo))),
                                IF(CHAR_LENGTH(posts.titulo) > 56, '...', '')
                            ) AS titulo, 
                            posts.descri,  
                            posts.preco,
                            fretes.descriResumida 
                        FROM 
                            posts
                        LEFT JOIN 
                            fretes ON fretes.id = posts.frete
                        WHERE 
                            FIND_IN_SET(posts.id, (
                                SELECT GROUP_CONCAT(idPost) 
                                FROM historico 
                                WHERE idUser = ?
                            )) > 0 
                        ORDER BY 
                            (SELECT data FROM historico WHERE idUser = ? AND idPost = posts.id) DESC
                        `;
        const [rows] = await conn.execute(query, [idUser, idUser]);
        res.send(rows);
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/returnImagemCapa", async (req, res) => {
    console.log("reimacap");
    const conn = await createMysqlConn();
    const { id } = req.body;
    try {
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
    } finally {
        conn.end();
    }
});

app.post("/api/returnImagensProduto", async (req, res) => {
    console.log("reimapro");
    const { id } = req.body;
    const conn = await createMysqlConn();
    try {
        const query =
            "SELECT imagem FROM imagenspost WHERE id = ? ORDER BY ordem";
        let [rows] = await conn.execute(query, [id]);
        if (rows.length > 0 && rows[0].imagem) {
            rows.forEach((element, i) => {
                console.log("foreachreimapro");
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
    } finally {
        conn.end();
    }
});

app.post("/api/mudarfotoperfil", async (req, res) => {
    console.log("mufope");
    const conn = await createMysqlConn();
    try {
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).json({ error: "Nenhum arquivo enviado." });
        }

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
    } finally {
        conn.end();
    }
});

app.post("/api/createpostitem", async (req, res) => {
    console.log("crepoite");
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
        conn.end();
    }
});

app.post("/api/createpostveiculo", async (req, res) => {
    console.log("crepovei");
    const { file0, file1, file2, file3 } = req.files;

    const {
        idUser,
        titlePost,
        descriPost,
        marca,
        modelo,
        versao,
        ano,
        cambio,
        combustivel,
        direcao,
        potencia,
        quilometragem,
        finalPlaca,
        corPost,
        precoPost,
    } = req.body;
    const conn = await createMysqlConn();

    try {
        const createPost = `INSERT INTO postsv (idUser, titulo, descri, marca, modelo, versao, ano, cambio, combustivel, direcao, potencia, quilometragem, finalPlaca, preco, cor) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        await conn.execute(createPost, [
            idUser,
            titlePost,
            descriPost,
            marca,
            modelo,
            versao,
            ano,
            cambio,
            combustivel,
            direcao,
            potencia,
            quilometragem,
            finalPlaca,
            precoPost,
            corPost,
        ]);

        const selLastId = `SELECT last_insert_id() id FROM postsv`;
        const [arrayRowid] = await conn.execute(selLastId);
        const lastId = arrayRowid[0].id;

        if (file0) {
            await salvarImagemBase64(file0, lastId, 0, "imagenspostv");
        }
        if (file1) {
            await salvarImagemBase64(file1, lastId, 1, "imagenspostv");
        }
        if (file2) {
            await salvarImagemBase64(file2, lastId, 2, "imagenspostv");
        }
        if (file3) {
            await salvarImagemBase64(file3, lastId, 3, "imagenspostv");
        }
    } catch (e) {
        console.log(e);
    } finally {
        res.json("");
        conn.end();
    }
});

app.post("/api/returnProduto", async (req, res) => {
    console.log("retpro");
    const conn = await createMysqlConn();
    try {
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
    } finally {
        conn.end();
    }
});

app.post("/api/retornaSellerInfos", async (req, res) => {
    console.log("resi");
    const conn = await createMysqlConn();
    try {
        const { id } = req.body;
        const query = `SELECT id, 
                                email, 
                                nome, 
                                vendas, 
                                avaliacao, 
                                TIMESTAMPDIFF(SECOND, users.dataCriacao, NOW()) dataCriacao 
                                FROM users 
                                WHERE id = ? 
                                LIMIT 1`;
        const [rows] = await conn.execute(query, [id]);
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(500).json({ error: "Erro interno do servidor" });
        }
    } catch (error) {
        console.error("Erro ao buscar imagem do perfil:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});
app.post("/api/retornaSellerData", async (req, res) => {
    console.log("resd");
    const conn = await createMysqlConn();
    try {
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
    } finally {
        conn.end();
    }
});

app.post("/api/createalgoritmo", async (req, res) => {
    console.log("ca");
    const conn = await createMysqlConn();
    try {
        const { idPost, idUser } = req.body;

        const query = `SELECT idPost FROM historico WHERE idPost = ? AND idUser = ?`;
        const [row] = await conn.execute(query, [idPost, idUser]);

        const sql = `SELECT count(idPost) count FROM historico WHERE idUser = ?`;
        const [count] = await conn.execute(sql, [idUser]);

        if (count[0].count >= 30) {
            const cretab = `CREATE TEMPORARY TABLE TempTable
                                        SELECT MIN(data) AS min_data
                                        FROM historico
                                        WHERE idUser = ?`;
            await conn.execute(cretab, [idUser]);
            const del = `DELETE FROM historico 
                               WHERE idUser = ?
                                 AND data = (SELECT min_data FROM TempTable);`;
            await conn.execute(del, [idUser]);
            const deltab = `DROP TEMPORARY TABLE IF EXISTS TempTable;`;
            await conn.execute(deltab);
        }

        if (!row[0]?.idPost) {
            const insert = `INSERT INTO historico (idPost, idUser) VALUES (?, ?)`;
            await conn.execute(insert, [idPost, idUser]);
        } else {
            const update = `UPDATE historico SET data = NOW() WHERE idPost = ? AND idUser = ?`;
            await conn.execute(update, [idPost, idUser]);
        }

        res.json(true);
    } catch (error) {
        console.error("Erro ao criar algoritmo:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/criaRelacionamentoCarrinho", async (req, res) => {
    console.log("crc");
    const conn = await createMysqlConn();
    try {
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
        console.error("Erro ao criar carrinho:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/deletaRelacaoCarrinho", async (req, res) => {
    console.log("drc");
    const conn = await createMysqlConn();
    try {
        const { idUser, idPost } = req.body;

        const alterTable = `DELETE FROM cart WHERE idUser = ? AND idPost = ?`;
        await conn.execute(alterTable, [idUser, idPost]);

        res.status(200).json({ created: true });
    } catch (error) {
        console.error("Erro ao deletar item no carrinho:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/denunciarAnuncio", async (req, res) => {
    console.log("denanun");
    const conn = await createMysqlConn();
    try {
        const { tipo, idPost, motivo, input, idUser, email } = req.body;

        const alterTable = `INSERT INTO denuncias (motivoDenuncia, descri, idUser, email, idPost, tipo) 
                                VALUES (?, ?, ?, ?, ?, ?)`;
        await conn.execute(alterTable, [
            motivo,
            input,
            idUser,
            email,
            idPost,
            tipo,
        ]);

        res.status(200).json({ deleted: true });
    } catch (error) {
        console.error("Erro ao denunciar:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/returnCarrinho", async (req, res) => {
    console.log("retucarr");
    const conn = await createMysqlConn();
    try {
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
    } finally {
        conn.end();
    }
});

app.post("/api/returnSearchList", async (req, res) => {
    console.log("retsealist");
    const conn = await createMysqlConn();
    try {
        const { tipo, search } = req.body;

        let sel = "";
        let arr = [];
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

            arr = [search, search];
        } else if (Number(tipo) == 1) {
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
                  LIMIT 80;`;
            arr = [search];
        }  else if(tipo.split("-")[0] == '2') {
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
                                AND users.id = ?
                    ORDER BY relevancia DESC, 
                                datacriacao DESC
                        LIMIT 80; `;
 
            arr = [search, search, tipo.split("-")[1]];
        }

        const [rows] = await conn.execute(sel, arr);
        res.json(rows || []);
    } catch (error) {
        console.error("Erro ao retornar search list:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/returnChats", async (req, res) => {
    console.log("retuchats");
    const conn = await createMysqlConn();
    try {
        const { id } = req.body;
 
        const query = `SELECT 
                            chat.idEnv, 
                            chat.idRec, 
                            chat.msg, 
                            chat.visualizado, 
                            chat.dataCriacao, 
                            idenv.nome idenvnome, 
                            idenv.email idenvemail, 
                            idrec.nome idrecnome, 
                            idrec.email idrecemail
                        FROM chat 
                        INNER JOIN users idenv ON idenv.id = chat.idEnv
                        INNER JOIN users idrec ON idrec.id = chat.idRec
                        WHERE chat.dataCriacao = (
                            SELECT MAX(dataCriacao)
                            FROM chat c
                            WHERE c.idRec = chat.idRec
                            AND c.idEnv = chat.idEnv
                        ) 
                        AND (idEnv = ? OR idRec = ?)
                        ORDER BY chat.dataCriacao DESC;
                        `;
        let [rows] = await conn.execute(query, [id, id]);
 
        let array = []
        for (let i = 0; i < rows.length; i++) {
            let num = rows[i].idEnv == id ? rows[i].idRec : rows[i].idEnv
            
            if(array.includes(num)) {
                rows.splice(i, 1)
                i --
                continue
            } 
    
            array.push(num)
            
            let msgDec = jab.decrypt(rows[i].msg);
            if (msgDec.length > 22) {
                msgDec = msgDec.slice(0, 19) + "...";
            }
            rows[i].msg = msgDec;
        }

        res.json(rows);
    } catch (error) {
        console.error("Erro ao buscar chats:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/returnChat", async (req, res) => {
    console.log("retuchat");
    const conn = await createMysqlConn();
    try {
        const { idUser, idParam } = req.body;
 
        const update = `UPDATE chat SET visualizado = ? WHERE idEnv = ? AND idRec = ? AND visualizado != ?`;
        await conn.execute(update, [1, idParam, idUser, 1]);
 
        const query = `SELECT DISTINCT chat.idEnv, 
                                        chat.idRec, 
                                        chat.msg, 
                                        chat.dataCriacao, 
                                        chat.visualizado, 
                                        idenv.nome idenvnome, 
                                        idrec.nome idrecnome, 
                                        idenv.email idenvemail, 
                                        idrec.email idrecemail
                                    FROM chat 
                              INNER JOIN users idenv ON idenv.id = chat.idEnv
                              INNER JOIN users idrec ON idrec.id = chat.idRec
                                  WHERE (idEnv = ? OR idRec = ?)  
                                    AND (idEnv = ? OR idRec = ?)
                                ORDER BY chat.dataCriacao
        `;
        const [rows] = await conn.execute(query, [
            idUser,
            idUser,
            idParam,
            idParam,
        ]);

        for (let i = 0; i < rows.length; i++) { 
            rows[i].msg = jab.decrypt(rows[i].msg); 
        }
 
        res.json(rows);
    } catch (error) {
        console.error("Erro ao buscar chat:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.post("/api/enviaMensagemChat", async (req, res) => {
    console.log("envmsgcha");
    const conn = await createMysqlConn();
    try {
        const { idEnv, idRec, msg } = req.body;
        const query = `INSERT INTO chat (idEnv, idRec, msg) VALUES (?, ?, ?)
        `;
        const [rows] = await conn.execute(query, [
            idEnv,
            idRec,
            jab.encrypt(msg.replace(/\n/g, "")),
        ]);

        for (let i = 0; i < rows.length; i++) {
            let msgDec = jab.decrypt(rows[i].msg);
            if (msgDec.length > 30) {
                msgDec = msgDec.slice(0, 27) + "...";
            }
            rows[i].msg = msgDec;
        }

        res.json(rows);
    } catch (error) {
        console.error("Erro ao buscar chat:", error);
        res.status(500).json({ error: "Erro interno do servidor" });
    } finally {
        conn.end();
    }
});

app.get("/", (req, res) => {
    res.send();
});

app.listen(port, () => {
    console.log("Server on");
});

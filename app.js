require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

//---- JSON
app.use(express.json());


//---- MODELS
const User = require('./models/User');
app.get("/", (req, res) => {
    res.status(200).json({ msg: "Bem vindo a API!" });
});


//---- TOKEN
app.get('/user/:id', async (req, res) => {
    const id = req.params.id;

    // EXISTE
    const user = await User.findById(id, '-password');
    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }
    res.status(200).json({ user });
});


//---- REGISTRO
app.post('/auth/register', async (req, res) => {
const { name, email, password, confirmpassword } = req.body;


//---- VALIDACAO
if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
}
if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" });
}
if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
}


//---- EXISTE
const userExists = await User.findOne({ email: email });
if (userExists) {
    return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" });
}


//---- SENHA
const salt = await bcrypt.genSalt(12);
const passwordHash = await bcrypt.hash(password, salt);


//---- USUARIO
const user = new User({
    name, email, password: passwordHash,
});

try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso!" });
} catch (error) {
    res.status(500).json({ msg: 'ERRO no servidor!' });
}
});


//---- LOGIN
app.post("/auth/login", async (req, res) => {
const { email, password } = req.body;
if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" });
}
if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
}


//---- EXISTE
const user = await User.findOne({ email: email });
if (!user) {
  return res.status(404).json({ msg: "Usuário não encontrado!" });
}


//---- SENHA
const checkPassword = await bcrypt.compare(password, user.password);
if (!checkPassword) {
  return res.status(422).json({ msg: "Senha inválida" });
}

try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      { id: user._id, },
      secret,); 
    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
} catch (error) {
    res.status(500).json({ msg: error });
}
})


//---- CREDENCIAIS
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.zbo6p8c.mongodb.net/?retryWrites=true&w=majority`)
.then(() => {
    app.listen(3000);
    console.log('Conectou ao banco!');
}).catch((err) => console.log(err));

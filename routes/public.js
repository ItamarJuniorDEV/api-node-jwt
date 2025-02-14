import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "defaultSecret";

// Cadastro
router.post("/cadastro", async (req, res) => {
  try {
    const user = req.body;
    console.log("Dados recebidos:", user);

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(user.password, salt);
    console.log("Password hash criado");

    const userDB = await prisma.user.create({
      data: {
        name: user.name,
        email: user.email,
        password: hashPassword,
      },
    });
    console.log("Usuário criado:", userDB);
    res.status(201).json(userDB);
  } catch (error) {
    console.error("Erro completo:", error);
    res.status(500).json({ message: "Erro no Servidor, tente novamente." });
  }
});

// Rota de teste para listar usuários
router.get("/teste", async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    console.log("Usuários encontrados:", users);
    res.json(users);
  } catch (error) {
    console.error("Erro ao buscar usuários:", error);
    res.status(500).json({ message: "Erro ao buscar usuários" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const userInfo = req.body;

    // Verifica se email e senha foram fornecidos
    if (!userInfo.email || !userInfo.password) {
      return res
        .status(400)
        .json({ message: "Email e senha são obrigatórios" });
    }

    // Busca o usuário no banco de dados
    const user = await prisma.user.findUnique({
      where: {
        email: userInfo.email,
      },
    });

    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const isMatch = await bcrypt.compare(userInfo.password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Senha inválida" });
    }

    // Gerar o Token JWT
    const token = jwt.sign({ id: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ user, token });
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).json({ message: "Erro no Servidor, tente novamente." });
  }
});

export default router;

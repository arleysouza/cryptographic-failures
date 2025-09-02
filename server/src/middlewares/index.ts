import { Request, Response, NextFunction } from "express";

// Middleware de autenticação
export function authentication(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (!req.cookies.userId) {
    res.status(401).json({ error: "Usuário não autenticado" });
  } else {
    next();
  }
}
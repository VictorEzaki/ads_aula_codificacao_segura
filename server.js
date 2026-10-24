import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import DOMPurify from 'isomorphic-dompurify';
import { PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// middleware de prevenção contra ataque CSRF
function csrfProtection(req, res, next) {
    if (req.method === 'GET') {
        const token = crypto.randomBytes(32).toString('hex');
        res.cookie('csrf_token', token, {
            httpOnly: true, 
            sameSite: 'strict',
        });
        req.csrfToken = token;
        return next();
    }
    
    const cookieToken = req.cookies.csrf_token;
    const formToken = req.body._csrf;
    
    if (!cookieToken || !formToken || cookieToken !== formToken) {
        return res.status(403).send('Erro 403: Ataque CSRF detectado! Token inválido.');
    }
    next();
}

// prevenção contra SQL injection
app.get('/busca', async (req, res) => {
    const termo = req.query.termo || '';
    
    // vulneravel: concatenar string diretamente na query
    // Ex: http://localhost:3000/busca?termo=' OR 'a'='a
    //const resultados = await prisma.$queryRawUnsafe(`SELECT * FROM comments WHERE author = '${termo}'`);
    
    // seguro: utilizar o query builder do prisma
    const resultados = await prisma.comment.findMany({
        where: { author: { contains: termo } }
    });
    
    res.json(resultados);
});

// prevenção contra XSS
app.post('/comentarios', csrfProtection, async (req, res) => {
    const { author, content } = req.body;
    
    // exemplo script: <script>alert('XSS')</script>
    
    const cleanAuthor = DOMPurify.sanitize(author);
    const cleanContent = DOMPurify.sanitize(content);
    
    await prisma.comment.create({
        data: {
            author: cleanAuthor,
            content: cleanContent,
        },
    });
    
    res.redirect('/');
});

// helper para escapar entidades html
function escapeHTML(str) {
    return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// rota de demonstração
app.get('/', csrfProtection, async (req, res) => {
    const comments = await prisma.comment.findMany();
    
    const commentsHtml = comments
    .map((c) => `<p><strong>${escapeHTML(c.author)}:</strong> ${escapeHTML(c.content)}</p>`)
    .join('');
    
    res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Demo de Codificação Segura</title>
    </head>
    <body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
      <h2>Mural de Comentários Seguro</h2>
      
      <form action="/comentarios" method="POST">
        <!-- Token oculto exigido para validar que o formulário veio do nosso próprio site (Anti-CSRF) -->
        <input type="hidden" name="_csrf" value="${req.csrfToken}" />
        
        <div>
          <label>Autor:</label><br/>
          <input type="text" name="author" required style="width: 100%; margin-bottom: 10px;" />
        </div>
        <div>
          <label>Comentário:</label><br/>
          <textarea name="content" required style="width: 100%; margin-bottom: 10px;"></textarea>
        </div>
        <button type="submit">Enviar Comentário</button>
      </form>
        
      <hr/>
      <h3>Comentários:</h3>
      ${commentsHtml}
    </body>
    </html>
  `);
    });
    
    app.listen(3000, () => console.log('Servidor rodando em http://localhost:3000'));
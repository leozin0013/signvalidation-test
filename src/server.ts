import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import multer, { MulterError } from 'multer';
import path from 'path';
import fs from 'fs';
import { spawn } from 'child_process';

const app = express();
const PORT = process.env.PORT || 3000;

// Interfaces
interface ValidationResult {
    success: boolean;
    error?: string;
    details?: string;
    signerInfo?: {
        name?: string;
        cpf?: string;
        cnpj?: string;
        issuer?: string;
        not_before?: string;
        not_after?: string;
    };
    validationResults?: Array<{
        signature_number: number;
        field_name?: string;
        valid: boolean;
        status?: string;
        intact?: boolean;
        trusted?: boolean;
        certificate?: any;
        error?: string;
    }>;
    totalSignatures?: number;
}

// Middlewares
app.use(cors());
app.use(express.json());

// Configurar armazenamento temporário para uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '..', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'pdf-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB max
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Apenas arquivos PDF são permitidos!'));
        }
    }
});

// Rota de teste
app.get('/', (req: Request, res: Response) => {
    res.json({
        message: 'API de Validação de Assinatura Digital',
        status: 'running',
        endpoints: {
            validate: 'POST /validate - Envia PDF para validação'
        }
    });
});

// Rota para validar assinatura do PDF
app.post('/validate', upload.single('pdf'), async (req: Request, res: Response): Promise<void> => {
    if (!req.file) {
        res.status(400).json({
            success: false,
            error: 'Nenhum arquivo PDF foi enviado'
        });
        return;
    }

    const pdfPath = req.file.path;
    console.log('Arquivo recebido:', req.file.originalname);
    console.log('Caminho:', pdfPath);

    try {
        // Chamar o script Python para validar a assinatura
        const validationResult = await validatePdfSignature(pdfPath);
        
        // Remover arquivo temporário
        fs.unlinkSync(pdfPath);
        
        res.json(validationResult);

    } catch (error) {
        console.error('Erro na validação:', error);
        
        // Remover arquivo temporário em caso de erro
        if (fs.existsSync(pdfPath)) {
            fs.unlinkSync(pdfPath);
        }
        
        const errorMessage = error instanceof Error ? error.message : 'Erro desconhecido';
        
        res.status(500).json({
            success: false,
            error: 'Erro ao processar a validação',
            details: errorMessage
        });
    }
});

// Função para chamar o script Python
function validatePdfSignature(pdfPath: string): Promise<ValidationResult> {
    return new Promise((resolve, reject) => {
        // Caminho do script Python
        const pythonScript = path.join(__dirname, '..', 'validate_signature.py');
        
        // Verificar se o script existe
        if (!fs.existsSync(pythonScript)) {
            return reject(new Error('Script Python não encontrado: ' + pythonScript));
        }

        console.log('Executando validação Python...');
        
        // Detectar comando Python baseado no ambiente
        // Linux/Docker: python3, Windows: python (ou python3 se instalado)
        const pythonCommand = process.platform === 'win32' ? 'python' : 'python3';
        
        // Spawnar processo Python
        const pythonProcess = spawn(pythonCommand, [pythonScript, pdfPath]);
        
        let stdout = '';
        let stderr = '';

        pythonProcess.stdout.on('data', (data: Buffer) => {
            stdout += data.toString();
        });

        pythonProcess.stderr.on('data', (data: Buffer) => {
            stderr += data.toString();
        });

        pythonProcess.on('close', (code: number) => {
            console.log('Python exit code:', code);
            console.log('Python stdout:', stdout);
            
            // Só mostrar stderr se houver erro real (exit code != 0)
            // Erros de revogação (soft-fail) são esperados e não são críticos
            if (code !== 0 && stderr) {
                console.log('Python stderr:', stderr);
            }
            
            if (code !== 0) {
                console.error('Erro Python (code ' + code + '):', stderr);
                const errorMsg = stderr || stdout || 'Processo Python falhou sem mensagem de erro';
                return reject(new Error(`Python script falhou (exit code ${code}): ${errorMsg}`));
            }

            try {
                // Parse do resultado JSON retornado pelo Python
                const result: ValidationResult = JSON.parse(stdout);
                console.log('Validação concluída:', result.success ? 'Válido' : 'Inválido');
                resolve(result);
            } catch (error) {
                console.error('Erro ao parsear resultado:', stdout);
                const errorMessage = error instanceof Error ? error.message : 'Erro desconhecido';
                reject(new Error('Falha ao processar resposta do validador: ' + errorMessage + '\nOutput: ' + stdout));
            }
        });

        pythonProcess.on('error', (error: Error) => {
            console.error('Erro ao executar Python:', error);
            reject(new Error('Erro ao executar Python: ' + error.message + '. Verifique se Python está instalado.'));
        });
    });
}

// Tratamento de erros do Multer
app.use((error: Error, req: Request, res: Response, next: NextFunction): void => {
    if (error instanceof MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            res.status(400).json({
                success: false,
                error: 'Arquivo muito grande. Tamanho máximo: 10MB'
            });
            return;
        }
        res.status(400).json({
            success: false,
            error: 'Erro no upload: ' + error.message
        });
        return;
    }
    
    if (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
        return;
    }
    
    next();
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log('Servidor rodando na porta', PORT);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('URL:', `http://localhost:${PORT}`);
});

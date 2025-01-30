import { z } from 'zod';
import { Logger } from '@nestjs/common';

const logger = new Logger('ConfigValidation');

export const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  DB_HOST: z.string().min(1, 'DB_HOST is required'),
  DB_PORT: z.coerce.number().default(5438),
  DB_USER: z.string().min(1, 'DB_USER is required'),
  DB_PASSWORD: z.string().min(1, 'DB_PASSWORD is required'),
  DB_NAME: z.string().min(1, 'DB_NAME is required'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
});

export const validateEnv = (env: NodeJS.ProcessEnv) => {
  const parsed = envSchema.safeParse(env);

  if (!parsed.success) {
    logger.error('❌ Error en la validación de variables de entorno');
    parsed.error.issues.forEach((issue) => {
      logger.error(`❌ [${issue.path.join('.')}] ${issue.message}`);
    });

    throw new Error(
      'Fallo en la validación del entorno. Verifica tu archivo .env.',
    );
  }

  logger.log('✅ Variables de entorno cargadas y validadas correctamente');
  return parsed.data;
};

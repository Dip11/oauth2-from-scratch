import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  // Read cookies on incoming requests — needed for our oauth_state cookie and later the session cookie.
  app.use(cookieParser());

  // Allow our Next.js frontend (different origin) to call us AND send cookies.
  // Without credentials:true on the server AND credentials:'include' on the fetch,
  // the browser silently drops the Cookie header on cross-origin requests.
  app.enableCors({
    origin: config.get<string>('FRONTEND_URL'),
    credentials: true,
  });

  const port = config.get<number>('PORT') ?? 4000;
  await app.listen(port);
  console.log(`Backend listening on http://localhost:${port}`);
}
bootstrap();

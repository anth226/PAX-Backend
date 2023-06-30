import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import {ValidationPipe} from '@nestjs/common'

async function bootstrap() {
  try {
    const PORT = process.env.PORT || 5000;
    const app = await NestFactory.create(AppModule, {
      cors: {
        credentials: true,
        // origin: '*',
        origin: process.env.CLIENT_URL,
      },
    });
    app.setGlobalPrefix('v1');
    app.useGlobalPipes(new ValidationPipe());
    const config = new DocumentBuilder()
      .setTitle('API')
      .setVersion('1.0.0')
      .setExternalDoc('For more information', 'http://swagger.io')
      .build(); // openapi info
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('/docs', app, document);
    await app.listen(PORT);
    console.log(`Server started on port - ${PORT}`);
  } catch (error) {
    console.log(error.message)
  }
}
bootstrap();

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { config } from 'dotenv';
import { RedisModule } from '@nestjs-modules/ioredis';
import { I18nModule, QueryResolver } from 'nestjs-i18n';
import * as path from 'path';
import { V1Module } from './modules/v1/v1.module';

config();

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      useFactory: () => ({
        type: 'mysql',
        host: process.env.MYSQL_HOST,
        port: Number(process.env.MYSQL_PORT),
        username: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DB,
        entities: [__dirname + '/modules/v1/**/entity/*.entity{.ts,.js}'],
        synchronize: true,
      }),
    }),
    RedisModule.forRootAsync({
      useFactory: () => ({
        config: {
          url: process.env.REDIS_URL ?? 'redis://localhost:6379',
          password: process.env.REDIS_PASSWORD ?? null,
        },
      }),
    }),
    I18nModule.forRootAsync({
      useFactory: () => ({
        fallbackLanguage: 'en',
        loaderOptions: {
          path: path.join(__dirname, '/locales/'),
          watch: true,
        },
        typesOutputPath: path.join(__dirname, '../src/generated/i18n.generated.ts'),
      }),
      resolvers: [new QueryResolver(['lang', 'l'])],
    }),
    V1Module,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}

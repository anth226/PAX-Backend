import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { config } from 'dotenv';
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
        V1Module
    ],
    controllers: [],
    providers: [],
})
export class AppModule {}
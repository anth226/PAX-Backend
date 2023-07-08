import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { TOSTextModule } from './tos/tos.module';

@Module({
  imports: [TOSTextModule, AuthModule],
})
export class V1Module {}

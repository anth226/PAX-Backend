import { Module } from '@nestjs/common';
import { TOSTextController } from './tos.controller';
import { TOSTextService } from './tos.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TOSTextEntity } from './entity/tos.entity';

@Module({
  providers: [TOSTextService],
  controllers: [TOSTextController],
  imports: [
    TypeOrmModule.forFeature([
      TOSTextEntity
    ])
  ],
  exports: [TOSTextService],
})
export class TOSTextModule {}
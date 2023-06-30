import { Module } from '@nestjs/common';
import { PhoneService } from './phone.service';
import { PhoneController } from './phone.controller';

@Module({
  providers: [PhoneService],
  controllers: [PhoneController],
  imports: [
  ],
  exports: [PhoneService],
})
export class PhoneModule {}
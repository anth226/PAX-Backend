import { ApiProperty } from '@nestjs/swagger';

export class TOSTextDto {
  @ApiProperty({ type: 'string' })
  text: string;
}
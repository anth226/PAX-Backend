import { ApiProperty } from '@nestjs/swagger';

export class TOSAcceptanceDto {
  @ApiProperty({ type: 'number', example: "ID of tos text table" })
  TOSTextID: number;
}

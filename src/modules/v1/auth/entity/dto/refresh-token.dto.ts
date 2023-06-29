import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({ example: 'jsllfl1l3l' })
  refreshToken: string;
}

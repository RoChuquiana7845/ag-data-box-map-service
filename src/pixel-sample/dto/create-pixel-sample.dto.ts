import { IsNotEmpty, IsString, IsUUID, IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreatePixelSampleDto {
  @ApiProperty({ example: 'P001', description: 'Código del píxel de muestra' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'POINT(-75.1 6.2)',
    description: 'Coordenadas del píxel en WKT',
  })
  @IsNotEmpty()
  @IsString()
  geom: string;

  @ApiProperty({ example: 12.5, description: 'Valor del píxel' })
  @IsNotEmpty()
  @IsNumber()
  value: number;

  @ApiProperty({
    example: 'uuid-sample',
    description: 'ID de la muestra asociada',
  })
  @IsNotEmpty()
  @IsUUID()
  sample: string;
}

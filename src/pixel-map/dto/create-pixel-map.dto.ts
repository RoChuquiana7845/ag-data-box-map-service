import { IsNotEmpty, IsString, IsUUID, IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreatePixelMapDto {
  @ApiProperty({ example: 'PM001', description: 'Código del píxel en el mapa' })
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

  @ApiProperty({ example: 15.8, description: 'Valor del píxel' })
  @IsNotEmpty()
  @IsNumber()
  value: number;

  @ApiProperty({ example: 'uuid-map', description: 'ID del mapa asociado' })
  @IsNotEmpty()
  @IsUUID()
  map: string;
}

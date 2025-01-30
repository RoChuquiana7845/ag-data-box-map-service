import {
  IsNotEmpty,
  IsString,
  IsUUID,
  IsOptional,
  IsNumber,
  IsBoolean,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateSampleGridDto {
  @ApiProperty({
    example: 'G001',
    description: 'Código de la grilla de muestras',
  })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Grilla de muestreo de zona A',
    description: 'Descripción de la grilla',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'POLYGON((-75.1 6.2, -75.2 6.2, -75.2 6.3, -75.1 6.3, -75.1 6.2))',
    description: 'Coordenadas de la grilla en WKT',
  })
  @IsNotEmpty()
  @IsString()
  geom: string;

  @ApiProperty({ example: 'uuid-area', description: 'ID del área asociada' })
  @IsNotEmpty()
  @IsUUID()
  area: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario que crea la grilla',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;

  @ApiProperty({ example: 100, description: 'Ancho de la grilla' })
  @IsNotEmpty()
  @IsNumber()
  width: number;

  @ApiProperty({ example: 200, description: 'Altura de la grilla' })
  @IsNotEmpty()
  @IsNumber()
  height: number;

  @ApiProperty({
    example: true,
    description: 'Indica si la grilla usa sensores',
  })
  @IsOptional()
  @IsBoolean()
  sensor_flag?: boolean;
}

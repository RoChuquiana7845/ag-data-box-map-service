import {
  IsNotEmpty,
  IsString,
  IsNumber,
  IsUUID,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateSampleDto {
  @ApiProperty({ example: 'S001', description: 'Código de la muestra' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Muestra de suelo',
    description: 'Descripción de la muestra',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'POINT(-75.1 6.2)',
    description: 'Coordenadas de la muestra en WKT',
  })
  @IsNotEmpty()
  @IsString()
  geom: string;

  @ApiProperty({
    example: 'uuid-area',
    description: 'ID del área donde se toma la muestra',
  })
  @IsNotEmpty()
  @IsUUID()
  area: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario que toma la muestra',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;

  @ApiProperty({ example: 100, description: 'Coordenada X en la imagen' })
  @IsOptional()
  @IsNumber()
  pixel_x?: number;

  @ApiProperty({ example: 200, description: 'Coordenada Y en la imagen' })
  @IsOptional()
  @IsNumber()
  pixel_y?: number;
}

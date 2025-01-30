import { IsNotEmpty, IsString, IsUUID, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateAttributeDto {
  @ApiProperty({ example: 'A001', description: 'Código del atributo' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Temperatura',
    description: 'Descripción en portugués',
  })
  @IsNotEmpty()
  @IsString()
  description_pt: string;

  @ApiProperty({ example: 'Temp', description: 'Acrónimo en portugués' })
  @IsNotEmpty()
  @IsString()
  acronym_pt: string;

  @ApiProperty({ example: 'Temperature', description: 'Descripción en inglés' })
  @IsNotEmpty()
  @IsString()
  description_en: string;

  @ApiProperty({ example: 'Temp', description: 'Acrónimo en inglés' })
  @IsNotEmpty()
  @IsString()
  acronym_en: string;

  @ApiProperty({
    example: 'Temperatura',
    description: 'Descripción en español',
  })
  @IsNotEmpty()
  @IsString()
  description_es: string;

  @ApiProperty({ example: 'Temp', description: 'Acrónimo en español' })
  @IsNotEmpty()
  @IsString()
  acronym_es: string;

  @ApiProperty({
    example: 'uuid-unit',
    description: 'ID de la unidad de medida (opcional)',
  })
  @IsUUID()
  @IsOptional()
  unit?: string;
}

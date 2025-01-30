import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateSoilTypeDto {
  @ApiProperty({ example: 'ST001', description: 'Código del tipo de suelo' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Solo argiloso',
    description: 'Descripción en portugués',
  })
  @IsNotEmpty()
  @IsString()
  description_pt: string;

  @ApiProperty({ example: 'Clay soil', description: 'Descripción en inglés' })
  @IsNotEmpty()
  @IsString()
  description_en: string;

  @ApiProperty({
    example: 'Suelo arcilloso',
    description: 'Descripción en español',
  })
  @IsNotEmpty()
  @IsString()
  description_es: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario que registra el tipo de suelo',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;
}

import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUnitMeasureDto {
  @ApiProperty({
    example: 'UM001',
    description: 'Código de la unidad de medida',
  })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Kilogramo',
    description: 'Descripción de la unidad de medida',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'kg',
    description: 'Acrónimo de la unidad de medida',
  })
  @IsNotEmpty()
  @IsString()
  acronym: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario que registra la unidad de medida',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;
}

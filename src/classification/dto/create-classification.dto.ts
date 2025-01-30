import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateClassificationDto {
  @ApiProperty({ example: 'C001', description: 'Código de la clasificación' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'uuid-attribute',
    description: 'ID del atributo asociado',
  })
  @IsNotEmpty()
  @IsUUID()
  attribute: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario que realiza la clasificación',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;

  @ApiProperty({
    example: 'uuid-soil-type',
    description: 'ID del tipo de suelo (opcional)',
  })
  @IsUUID()
  soil_type?: string;

  @ApiProperty({
    example: 'uuid-entity',
    description: 'ID de la entidad (opcional)',
  })
  @IsUUID()
  organization?: string;
}

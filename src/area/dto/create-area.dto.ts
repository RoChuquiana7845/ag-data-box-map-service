import { IsNotEmpty, IsString, IsNumber, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateAreaDto {
  @ApiProperty({ example: 'A001', description: 'Código del área' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Área de investigación',
    description: 'Descripción del área',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({ example: 250.5, description: 'Tamaño del área en hectáreas' })
  @IsNotEmpty()
  @IsNumber()
  size: number;

  @ApiProperty({
    example: 'POLYGON((-75.1 6.2, -75.2 6.2, -75.2 6.3, -75.1 6.3, -75.1 6.2))',
    description: 'Coordenadas del polígono en WKT',
  })
  @IsNotEmpty()
  @IsString()
  geom: string; // Se enviará como WKT (Well-Known Text)

  @ApiProperty({
    example: 'uuid-soiltype',
    description: 'ID del tipo de suelo',
  })
  @IsUUID()
  soil_type?: string;

  @ApiProperty({
    example: 'uuid-project',
    description: 'ID del proyecto asociado',
  })
  @IsUUID()
  project?: string;

  @ApiProperty({ example: 'uuid-user', description: 'ID del usuario creador' })
  @IsNotEmpty()
  @IsUUID()
  user: string;
}

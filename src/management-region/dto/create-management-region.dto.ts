import { IsNotEmpty, IsString, IsUUID, IsInt } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateManagementRegionDto {
  @ApiProperty({
    example: 'Zona de Manejo A',
    description: 'Descripción de la zona de manejo',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'POLYGON((-75.1 6.2, -75.2 6.2, -75.2 6.3, -75.1 6.3, -75.1 6.2))',
    description: 'Coordenadas de la zona de manejo en WKT',
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
    description: 'ID del usuario responsable de la zona',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;

  @ApiProperty({
    example: 'k-means',
    description: 'Método de creación de la zona',
  })
  @IsNotEmpty()
  @IsString()
  zone_creation_method: string;

  @ApiProperty({ example: 3, description: 'Cantidad de clases en la zona' })
  @IsNotEmpty()
  @IsInt()
  zone_class_count: number;
}

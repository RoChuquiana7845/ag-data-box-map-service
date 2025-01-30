import { IsNotEmpty, IsString, IsUUID, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateMapDto {
  @ApiProperty({ example: 'M001', description: 'Código del mapa' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Mapa de interpolación',
    description: 'Descripción del mapa',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'POLYGON((-75.1 6.2, -75.2 6.2, -75.2 6.3, -75.1 6.3, -75.1 6.2))',
    description: 'Coordenadas del mapa en WKT',
  })
  @IsNotEmpty()
  @IsString()
  geom: string;

  @ApiProperty({ example: 'uuid-area', description: 'ID del área asociada' })
  @IsUUID()
  @IsOptional()
  area?: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario que creó el mapa',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;
}

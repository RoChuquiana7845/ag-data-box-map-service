import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateSamplePointDto {
  @ApiProperty({
    example: 'SP001',
    description: 'Código del punto de muestreo',
  })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'POINT(-75.1 6.2)',
    description: 'Coordenadas del punto de muestreo en WKT',
  })
  @IsNotEmpty()
  @IsString()
  geom: string;

  @ApiProperty({
    example: 'uuid-sample-grid',
    description: 'ID de la grilla de muestras asociada',
  })
  @IsNotEmpty()
  @IsUUID()
  sample_grid: string;
}

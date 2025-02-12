import {
  IsNotEmpty,
  IsString,
  IsNumber,
  IsUUID,
  IsObject,
} from 'class-validator';
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
    example: '46f51015-82f7-4c3e-ad24-cada101c5fb9',
    description: 'ID del proyecto asociado',
  })
  @IsUUID()
  projectId: string;

  @ApiProperty({
    example: { address: 'Calle 123', coordinates: { lat: -75.2, lng: 6.3 } },
    description: 'Ubicación del área',
  })
  @IsNotEmpty()
  @IsObject()
  location: {
    address: string;
    coordinates: { lat: number; lng: number };
  };
}

import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsObject, IsUUID } from 'class-validator';

export class CreateGeometryDto {
  @ApiProperty({
    example: 'b9d51fe7-8ebd-447b-bb65-a0cf514f8e2f',
    description: 'ID del área asociada',
  })
  @IsNotEmpty()
  @IsUUID()
  areaId: string;

  @ApiProperty({
    example: {
      type: 'Polygon',
      coordinates: [
        [
          [0, 0],
          [1, 1],
          [1, 0],
          [0, 0],
        ],
      ],
    },
    description: 'Geometría del área en formato GeoJSON.',
  })
  @IsNotEmpty()
  @IsObject()
  geom: {
    type: 'Polygon';
    coordinates: number[][][];
  };

  @ApiProperty({
    example: {
      fillColor: '#FF0000',
      strokeColor: '#000000',
      fillOpacity: 0.5,
      strokeWidth: 2,
    },
    description: 'Estilos de la geometría.',
  })
  @IsNotEmpty()
  @IsObject()
  style: {
    fillColor: string;
    strokeColor: string;
    fillOpacity: number;
    strokeWidth: number;
  };
}

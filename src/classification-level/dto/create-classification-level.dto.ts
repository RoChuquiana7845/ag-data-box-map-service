import { IsNotEmpty, IsString, IsUUID, IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateClassificationLevelDto {
  @ApiProperty({
    example: 'CL001',
    description: 'Código del nivel de clasificación',
  })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({ example: 1, description: 'Nivel de clasificación' })
  @IsNotEmpty()
  @IsNumber()
  level: number;

  @ApiProperty({ example: 0.1, description: 'Valor mínimo del nivel' })
  @IsNotEmpty()
  @IsNumber()
  minimum_value: number;

  @ApiProperty({ example: 1.0, description: 'Valor máximo del nivel' })
  @IsNotEmpty()
  @IsNumber()
  maximum_value: number;

  @ApiProperty({ example: '#FF0000', description: 'Color representativo' })
  @IsNotEmpty()
  @IsString()
  color: string;

  @ApiProperty({
    example: 'uuid-classification',
    description: 'ID de la clasificación asociada',
  })
  @IsNotEmpty()
  @IsUUID()
  classification: string;
}

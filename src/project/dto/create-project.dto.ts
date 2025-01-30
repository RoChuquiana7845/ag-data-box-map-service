import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateProjectDto {
  @ApiProperty({ example: 'Proyecto 1', description: 'Nombre del proyecto' })
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiProperty({
    example: 'Descripción del proyecto',
    description: 'Descripción detallada',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario creador del proyecto',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;
}

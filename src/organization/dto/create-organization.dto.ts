import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateOrganizationDto {
  @ApiProperty({ example: 'ORG001', description: 'Código de la organización' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'Ministerio de Medio Ambiente',
    description: 'Descripción de la organización',
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    example: 'Pichincha',
    description: 'Estado o provincia de la organización',
  })
  @IsNotEmpty()
  @IsString()
  state: string;

  @ApiProperty({ example: 'Quito', description: 'Ciudad de la organización' })
  @IsNotEmpty()
  @IsString()
  city: string;

  @ApiProperty({
    example: 'uuid-user',
    description: 'ID del usuario responsable de la organización',
  })
  @IsNotEmpty()
  @IsUUID()
  user: string;
}

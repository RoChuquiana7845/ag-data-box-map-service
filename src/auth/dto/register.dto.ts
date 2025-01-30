import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @ApiProperty({ example: 'Juan Pérez', description: 'Nombre del usuario' })
  @IsString({ message: 'El nombre debe ser un texto válido' })
  name: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'Correo electrónico',
  })
  @IsEmail({}, { message: 'El correo electrónico no es válido' })
  email: string;

  @ApiProperty({
    example: 'mypassword',
    description: 'Contraseña',
    minLength: 6,
  })
  @IsString({ message: 'La contraseña debe ser un texto válido' })
  @MinLength(6, { message: 'La contraseña debe tener al menos 6 caracteres' })
  password: string;
}

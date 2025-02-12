import { IsEmail, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ example: 'Juan Pérez', description: 'Nombre del usuario' })
  @IsString()
  name: string;

  @ApiProperty({
    example: 'useri@example.com',
    description: 'Correo electrónico',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'mypassword',
    description: 'Contraseña',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'User', description: 'Rol del usuario' })
  @IsString()
  role: 'User' | 'Analyst' | 'Admin';
}

import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Request,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UserPayload } from './interfaces/user-play-load.interface';
import { LocalAuthGuard } from './guards/local-auth.guard';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { UserPayloadDto } from './dto/user-payload.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Registrar un usuario' })
  @ApiResponse({ status: 201, description: 'Usuario registrado correctamente' })
  @ApiResponse({
    status: 409,
    description: 'El correo electrónico ya está en uso',
  })
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    try {
      return await this.authService.register(registerDto);
    } catch (error) {
      throw new HttpException(
        (error as Error).message,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @ApiOperation({ summary: 'Iniciar sesión' })
  @ApiResponse({ status: 200, description: 'Devuelve un token JWT' })
  @ApiResponse({ status: 401, description: 'Credenciales incorrectas' })
  @UseGuards(LocalAuthGuard)
  @Post('login')
  login(@Request() req: { user: UserPayloadDto }) {
    try {
      return this.authService.login(req.user);
    } catch (error) {
      throw new HttpException(
        (error as Error).message,
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  @ApiBearerAuth()
  @ApiOperation({ summary: 'Obtener perfil del usuario autenticado' })
  @ApiResponse({ status: 200, description: 'Devuelve el perfil del usuario' })
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req: { user: UserPayload }) {
    try {
      return req.user;
    } catch (error) {
      throw new HttpException(
        'Error al obtener perfil:' + (error as Error).message,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}

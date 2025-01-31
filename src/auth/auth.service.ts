import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayloadDto } from './dto/user-payload.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    try {
      const existingUser = await this.userRepository.findOne({
        where: { email: registerDto.email },
      });

      if (existingUser) {
        throw new ConflictException('El correo electrónico ya está en uso');
      }

      const user = this.userRepository.create(registerDto);
      await this.userRepository.save(user);

      const payload = { sub: user.id, email: user.email, role: user.role };
      const token = this.jwtService.sign(payload);

      return {
        message: 'Usuario registrado correctamente',
        access_token: token,
      };
    } catch (error) {
      throw new InternalServerErrorException(
        'Error al registrar usuario: ' + error,
      );
    }
  }

  login(user: UserPayloadDto) {
    try {
      const payload = { sub: user.id, email: user.email, role: user.role };
      return { access_token: this.jwtService.sign(payload) };
    } catch (error) {
      throw new InternalServerErrorException('Error al iniciar sesión' + error);
    }
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<UserPayloadDto | null> {
    try {
      const user = await this.userRepository.findOne({ where: { email } });

      if (!user) {
        this.logger.warn(`Usuario no encontrado con email: ${email}`);
        return null;
      }

      this.logger.debug(`Usuario encontrado: ${user.email}`);
      this.logger.debug(`Password: ${password}`);
      const isPasswordValid = await bcrypt.compare(
        password.trim(),
        user.password,
      );
      if (!isPasswordValid) {
        return null;
      }

      return {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      };
    } catch (error) {
      throw new InternalServerErrorException(
        'Error al validar usuario' + error,
      );
    }
  }
}

import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  BeforeInsert,
  Unique,
} from 'typeorm';
import * as bcrypt from 'bcrypt';

@Unique(['email'])
@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  name: string;

  @Column()
  password: string;

  @Column({ default: 'user' })
  role: string;

  @BeforeInsert()
  async hashPassword(): Promise<void> {
    let salt: string;
    let hashedPassword: string;

    try {
      salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(this.password, salt);

      this.password = hashedPassword;
    } catch (err: unknown) {
      throw new Error(
        `Error al hashear la contraseña: ${(err as Error).message}`,
      );
    }
  }
}

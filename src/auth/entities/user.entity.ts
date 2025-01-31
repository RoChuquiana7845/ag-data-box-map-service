import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  BeforeInsert,
  Unique,
  BeforeUpdate,
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
  @BeforeUpdate()
  async hashPassword(): Promise<void> {
    try {
      if (!this.password || this.password.startsWith('$2b$')) return;

      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    } catch (err: unknown) {
      throw new Error(
        `Error al hashear la contraseña: ${(err as Error).message}`,
      );
    }
  }
}

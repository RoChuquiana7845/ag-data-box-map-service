import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  BeforeInsert,
  OneToMany,
  CreateDateColumn,
} from 'typeorm';
import * as bcrypt from 'bcrypt';
import { Project } from 'src/project/entities/project.entity';

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

  @Column({ default: 'User' })
  role: 'User' | 'Analyst' | 'Admin';

  @OneToMany(() => Project, (project) => project.user)
  projects: Project[];

  @Column({ default: 'active' })
  status: 'active' | 'inactive';

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @BeforeInsert()
  async hashPassword(): Promise<void> {
    if (!this.password.startsWith('$2b$')) {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    }
  }
}

import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Attribute } from '../../attribute/entities/attribute.entity';
import { User } from '../../user/entities/user.entity';
import { SoilType } from '../../soil-type/entities/soil-type.entity';
import { Organization } from 'src/organization/entities/organization.entity';

@Entity('classifications')
export class Classification {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @ManyToOne(() => Attribute, { nullable: false })
  attribute: Attribute;

  @ManyToOne(() => User, { nullable: false })
  user: User;

  @ManyToOne(() => SoilType, { nullable: true })
  soil_type: SoilType;

  @ManyToOne(() => Organization, { nullable: true })
  organization: Organization;
}

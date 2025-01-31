import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from './entities/organization.entity';
import { CreateOrganizationDto } from './dto/create-organization.dto';
import { UpdateOrganizationDto } from './dto/update-organization.dto';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class OrganizationService {
  constructor(
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
  ) {}

  async findAll(): Promise<Organization[]> {
    return this.organizationRepository.find({ relations: ['user'] });
  }

  async findOne(id: string): Promise<Organization> {
    const organization = await this.organizationRepository.findOne({
      where: { id },
      relations: ['user'],
    });
    if (!organization)
      throw new NotFoundException(`Organización con ID ${id} no encontrada`);
    return organization;
  }

  async create(
    createOrganizationDto: CreateOrganizationDto,
  ): Promise<Organization> {
    const organization = this.organizationRepository.create({
      ...createOrganizationDto,
      user: { id: createOrganizationDto.user } as User,
    });

    await this.organizationRepository.save(organization);
    return organization;
  }

  async update(
    id: string,
    updateOrganizationDto: UpdateOrganizationDto,
  ): Promise<Organization> {
    const organization = await this.findOne(id);
    Object.assign(organization, updateOrganizationDto);

    return this.organizationRepository.save(organization);
  }

  async remove(id: string): Promise<void> {
    const organization = await this.findOne(id);
    await this.organizationRepository.remove(organization);
  }
}

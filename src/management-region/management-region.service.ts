import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ManagementRegion } from './entities/management-region.entity';
import { CreateManagementRegionDto } from './dto/create-management-region.dto';
import { UpdateManagementRegionDto } from './dto/update-management-region.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { Area } from 'src/area/entities/area.entity';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class ManagementRegionService {
  constructor(
    @InjectRepository(ManagementRegion)
    private readonly managementRegionRepository: Repository<ManagementRegion>,
  ) {}

  async findAll(): Promise<ManagementRegion[]> {
    return this.managementRegionRepository.find({
      relations: ['area', 'user'],
    });
  }

  async findOne(id: string): Promise<ManagementRegion> {
    const region = await this.managementRegionRepository.findOne({
      where: { id },
      relations: ['area', 'user'],
    });
    if (!region)
      throw new NotFoundException(`Zona de manejo con ID ${id} no encontrada`);
    return region;
  }

  async create(
    createManagementRegionDto: CreateManagementRegionDto,
  ): Promise<ManagementRegion> {
    const region = this.managementRegionRepository.create({
      ...createManagementRegionDto,
      geom: parse(createManagementRegionDto.geom) as Geometry,
      area: { id: createManagementRegionDto.area } as Area,
      user: { id: createManagementRegionDto.user } as User,
    });

    await this.managementRegionRepository.save(region);
    return region;
  }

  async update(
    id: string,
    updateManagementRegionDto: UpdateManagementRegionDto,
  ): Promise<ManagementRegion> {
    const region = await this.findOne(id);
    Object.assign(region, updateManagementRegionDto);

    return this.managementRegionRepository.save(region);
  }

  async remove(id: string): Promise<void> {
    const region = await this.findOne(id);
    await this.managementRegionRepository.remove(region);
  }
}

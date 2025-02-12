import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Project } from './entities/project.entity';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import {
  ProjectListResponse,
  ProjectResponse,
  SuccessResponse,
} from './types/project-responses';
import { User } from 'src/auth/entities/user.entity';

@Injectable()
export class ProjectService {
  constructor(
    @InjectRepository(Project)
    private readonly projectRepository: Repository<Project>,
  ) {}

  async findAll(page: number, limit: number): Promise<ProjectListResponse> {
    const [projects, total] = await this.projectRepository.findAndCount({
      take: limit,
      skip: (page - 1) * limit,
      relations: ['user'],
    });

    return {
      success: true,
      data: projects.map((p) => ({
        id: p.id,
        name: p.name,
        description: p.description,
        userId: p.user.id,
        date: p.date,
      })),
      pagination: { total, page, limit },
    };
  }

  async findOne(id: string): Promise<ProjectResponse> {
    const project = await this.projectRepository.findOne({
      where: { id },
      relations: ['user'],
    });
    if (!project)
      throw new NotFoundException(`Proyecto con ID ${id} no encontrado`);

    return {
      success: true,
      data: {
        id: project.id,
        name: project.name,
        description: project.description,
        userId: project.user.id,
        date: project.date,
      },
    };
  }

  async create(
    createProjectDto: CreateProjectDto,
    userId: string,
  ): Promise<ProjectResponse> {
    const project = this.projectRepository.create({
      ...createProjectDto,
      user: { id: userId } as User,
    });
    await this.projectRepository.save(project);
    return this.findOne(project.id);
  }

  async update(
    id: string,
    updateProjectDto: UpdateProjectDto,
  ): Promise<ProjectResponse> {
    await this.projectRepository.update(id, updateProjectDto);
    return this.findOne(id);
  }

  async remove(id: string): Promise<SuccessResponse> {
    await this.projectRepository.delete(id);
    return { success: true };
  }
}

import { PartialType } from '@nestjs/mapped-types';
import { CreateManagementRegionDto } from './create-management-region.dto';

export class UpdateManagementRegionDto extends PartialType(
  CreateManagementRegionDto,
) {}

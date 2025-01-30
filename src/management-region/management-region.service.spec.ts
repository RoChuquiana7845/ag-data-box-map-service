import { Test, TestingModule } from '@nestjs/testing';
import { ManagementRegionService } from './management-region.service';

describe('ManagementRegionService', () => {
  let service: ManagementRegionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ManagementRegionService],
    }).compile();

    service = module.get<ManagementRegionService>(ManagementRegionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

#ifndef NPU_DRIVER_H
#define NPU_DRIVER_H

#include "rknpu-ioctl.h"

struct rknpu_device;

int rknpu_init(struct rknpu_device **rknpu_dev,
               unsigned long base_paddr[], unsigned long iommu_base_paddr[],
               unsigned long rknpu_irqs[]);

int rknpu_submit(struct rknpu_device *rknpu_dev, struct rknpu_submit *data);
int rknpu_submit_multi(struct rknpu_device *rknpu_dev, struct rknpu_submit *args[], int task_num, void *polling);

int rknpu_soft_reset(struct rknpu_device *rknpu_dev);

#endif /* NPU_DRIVER_H */
